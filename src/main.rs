use std::collections::HashMap;
use std::env::args;
use std::fmt::Display;
use std::fs::{metadata, read_to_string};
use std::io::{BufRead, BufReader, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use std::net::{IpAddr, Ipv6Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::{sleep, spawn};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "htpasswd")]
mod ncsa;
#[cfg(feature = "htpasswd")]
use ncsa::Htpasswd;

mod http;
use http::{Headers, Host, Request, Response, Uri};

mod time;
use time::LocalTime;

enum Errors {
    I(IoError),
    O(IoError),
}

#[inline]
fn unmap_ipv4_in_ipv6(addr: &IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.segments() {
            [0, 0, 0, 0, 0, 0xFFFF, hi, lo] => IpAddr::V4(((hi as u32) << 16 | lo as u32).into()),
            _ => *addr,
        }
        _ => *addr,
    }
}

fn is_forbidden(addr: &IpAddr, forbid_loopback: bool) -> bool {
    let addr = unmap_ipv4_in_ipv6(addr);
    if addr.is_loopback() { return forbid_loopback }
    addr.is_unspecified() || addr.is_multicast() || match addr {
        IpAddr::V4(addr) => addr.is_link_local() || addr.is_broadcast(),
        IpAddr::V6(addr) => (addr.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_hostname(hostname: &str) -> bool {
    hostname.split('.').all(|s| {
        s.len() > 0 &&
        s.chars().next().unwrap().is_ascii_alphanumeric() &&
        s.chars().last().unwrap().is_ascii_alphanumeric() &&
        s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn copy_all<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64, Errors> {
    let mut buf = [0; 8192];
    let mut len: u64 = 0;
    loop {
        match reader.read(&mut buf) {
            Ok(n) => {
                if n == 0 { return Ok(len) }
                if let Err(e) = writer.write_all(&buf[..n]) { return Err(Errors::O(e)) }
                len += n as u64;
            }
            Err(e) => return Err(Errors::I(e))
        }
    }
}

fn copy_exact<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut len: u64) -> Result<(), Errors> {
    let mut buf = [0; 8192];
    Ok(while len > 0 {
        let n = len.min(buf.len() as u64) as usize;
        if let Err(e) = reader.read_exact(&mut buf[..n]) { return Err(Errors::I(e)) }
        if let Err(e) = writer.write_all(&buf[..n]) { return Err(Errors::O(e)) }
        len -= n as u64;
    })
}

fn copy_chunked<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64, Errors> {
    let mut buf = Vec::with_capacity(8192);
    let mut len = 0;
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(n) => {
                if !buf.ends_with(b"\r\n") { return Err(Errors::I(IoErrorKind::InvalidData.into())) }
                if let Err(e) = writer.write_all(&buf[..n]) { return Err(Errors::O(e)) }
                len += n as u64;
                let hex = String::from_iter(buf[..n-2].iter().map(|c| *c as char));
                if let Ok(n) = usize::from_str_radix(&hex, 16) {
                    let n = n + 2;
                    buf.resize(n, 0);
                    match reader.read_exact(&mut buf) {
                        Ok(_) => {
                            if !buf.ends_with(b"\r\n") { return Err(Errors::I(IoErrorKind::InvalidData.into())) }
                            if let Err(e) = writer.write_all(&buf[..n]) { return Err(Errors::O(e)) }
                        }
                        Err(e) => {
                            return Err(Errors::I(e))
                        }
                    }
                    len += n as u64;
                    if n == 2 { return Ok(len) }
                } else {
                    return Err(Errors::I(IoErrorKind::InvalidData.into()))
                }
            }
            Err(e) => {
                return Err(Errors::I(e))
            }
        }
    }
}

fn copy_body<R: BufRead, W: Write>(headers: &Headers, reader: &mut R, writer: &mut W) -> Result<u64, Errors> {
    if headers.contains("Transfer-Encoding", "chunked") {
        copy_chunked(reader, writer)
    } else if let Some(len) = headers.get_content_length() {
        match copy_exact(reader, writer, len) { Ok(_) => Ok(len), Err(e) => Err(e) }
    } else {
        copy_all(reader, writer)
    }
}

#[derive(Clone)]
struct Resolver {
    cache: Arc<RwLock<HashMap<String, (IpAddr, SystemTime)>>>,
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    ttl: Duration,
}

impl Resolver {
    fn new(hosts_files: Vec<String>, ttl: Duration) -> Self {
        let hosts_files = Arc::new(hosts_files);
        let mut hosts = HashMap::new();
        for data in hosts_files.iter().filter_map(|path| read_to_string(path).ok()) {
            Self::parse(&data, &mut hosts)
        }
        let hosts_reader = Arc::new(RwLock::new(hosts));
        let hosts_writer = hosts_reader.clone();
        spawn(move || {
            let f = |mtime, path|
                metadata(&path).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH).max(mtime);
            let mut lastmtime = hosts_files.iter().fold(UNIX_EPOCH, f);
            loop {
                sleep(Duration::from_secs(4));
                let mtime = hosts_files.iter().fold(UNIX_EPOCH, f);
                if mtime == lastmtime { continue }
                lastmtime = mtime;
                let mut hosts = HashMap::new();
                for data in hosts_files.iter().filter_map(|path| read_to_string(&path).ok()) {
                    Self::parse(&data, &mut hosts)
                }
                let mut writer = hosts_writer.write().unwrap();
                writer.clear();
                for (k, v) in hosts {
                    writer.insert(k, v);
                }
            }
        });
        Self { cache: Arc::new(RwLock::new(HashMap::new())), hosts: hosts_reader, ttl }
    }

    fn parse(data: &str, hosts: &mut HashMap<String, Vec<IpAddr>>) {
        for line in data.split('\n').filter(|s| s.len() > 0 && !s.starts_with('#')) {
            let mut iter = line.split_ascii_whitespace().filter(|s| s.len() > 0);
            if let Some(addr) = iter.next().and_then(|s| s.parse().ok()) {
                for s in iter {
                    hosts.entry(s.to_ascii_lowercase()).or_default().push(addr)
                }
            }
        }
    }

    fn get(&self, hostname: &str) -> Option<IpAddr> {
        self.hosts.read().unwrap().iter().find(|(pat, _)| match pat.as_str() {
            pat if !pat.starts_with("*.") => pat.eq_ignore_ascii_case(hostname),
            pat => pat[2..].eq_ignore_ascii_case(hostname)
                      || pat.len() <= hostname.len() && pat[1..].eq_ignore_ascii_case(&hostname[(hostname.len() + 1 - pat.len())..])
        })
        .map(|(_, addrs)| addrs[0])
    }

    fn resolve(&self, hostname: &str) -> IoResult<IpAddr> {
        if let Some(addr) = self.get(hostname) { return Ok(addr) }
        let now = SystemTime::now();
        if let Some((addr, eol)) = self.cache.read().unwrap().get(hostname) {
            if now < *eol { return Ok(*addr) }
        }
        let addr = format!("{}:0", hostname).to_socket_addrs()?.next().unwrap().ip();
        self.cache.write().unwrap().insert(hostname.into(), (addr, now + self.ttl));
        Ok(addr)
    }
}

struct ReqInfo {
    remote_addr: IpAddr,
    req_time: LocalTime,
    method: String,
    target: String,
    protocol: String,
}

enum AccessLog {
    Enabled(ReqInfo),
    Disabled,
}

impl AccessLog {
    fn new(remote_addr: IpAddr, req_time: LocalTime, req: &Request) -> Self {
        Self::Enabled(ReqInfo {
            remote_addr,
            req_time,
            method: req.method.clone(),
            target: req.target.clone(),
            protocol: req.protocol.clone(),
        })
    }

    fn print<N: Display>(&self, status: u16, sent: N) {
        match self {
            Self::Enabled(info) => {
                println!("{} - - [{}] \"{} {} {}\" {} {}",
                    info.remote_addr, info.req_time, info.method, info.target, info.protocol, status, sent);
            }
            Self::Disabled => {}
        }
    }
}

fn main() -> IoResult<()> {
    const BAD_REQUEST: &[u8] = b"\
        HTTP/1.1 400 Bad Request\r\n\
        \r\n";
    const FORBIDDEN: &[u8] = b"\
        HTTP/1.1 403 Forbidden\r\n\
        \r\n";
    #[cfg(feature = "htpasswd")]
    const PROXY_AUTHENTICATION_REQUIRED: &[u8] = b"\
        HTTP/1.1 407 Proxy Authentication Required\r\n\
        Proxy-Authentication: Basic\r\n\
        Proxy-Connection: close\r\n\
        \r\n";
    const NOT_IMPLEMENTED: &[u8] = b"\
        HTTP/1.1 501 Not Implemented\r\n\
        \r\n";
    const BAD_GATEWAY: &[u8] = b"\
        HTTP/1.1 502 Bad Gateway\r\n\
        \r\n";
    const HTTP_VERSION_NOT_SUPPORTED: &[u8] = b"\
        HTTP/1.1 505 HTTP Version Not Supported\r\n\
        \r\n";

    let print_help_and_exit = |code| -> ! {
        eprintln!("Usage: rwp [options...]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  -h, --help           Show this help message and exit");
        eprintln!("  -s, --silent         Decrease verbosity");
        eprintln!("  -v, --verbose        Increase verbosity");
        eprintln!("  -a, --address <addr> Listen on address (default: [::])");
        eprintln!("  -l, --localhost      Allow localhost as upstream");
        eprintln!("  -H, --hosts <path>   Hosts files to be read in addition to /etc/hosts");
        eprintln!("  -p, --port <number>  Listen on port (default: 8080)");
        exit(code)
    };
    let (verbosity, address, localhost, hosts_files, port) = {
        let mut verbosity = 1;
        let mut address = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let mut localhost = false;
        let mut hosts = vec!["/etc/hosts".into()];
        let mut port = 8080;
        let mut iter = args().skip(1);
        while let Some(k) = iter.next() {
            match k.as_str() {
                "-h" | "--help"      => print_help_and_exit(0),
                "-s" | "--silent"    => verbosity -= 1,
                "-v" | "--verbose"   => verbosity += 1,
                "-vv"                => verbosity += 2,
                "-a" | "--address" => match iter.next().and_then(|v| v.parse().ok()) {
                    Some(v) => address = v,
                    None => print_help_and_exit(1)
                }
                "-l" | "--localhost" => localhost = true,
                "-H" | "--hosts" => match iter.next() {
                    Some(v) => hosts.push(v),
                    None => print_help_and_exit(1)
                }
                "-p" | "--port" => match iter.next().and_then(|v| v.parse().ok()) {
                    Some(v) => port = v,
                    None => print_help_and_exit(1)
                }
                _ => print_help_and_exit(1)
            }
        }
        (verbosity, address, localhost, hosts, port)
    };
    let forbid_loopback = !localhost;
    let resolver = Resolver::new(hosts_files, Duration::from_secs(120));
    #[cfg(feature = "htpasswd")]
    let htpasswd = Htpasswd::new();

    let listener = TcpListener::bind((address, port))?;
    Ok(for incoming in listener.incoming() {
        match incoming {
            Ok(mut downstream) => {
                let remote_addr = unmap_ipv4_in_ipv6(&downstream.peer_addr().unwrap().ip());
                let req_time = LocalTime::now();
                let resolver = resolver.clone();
                #[cfg(feature = "htpasswd")]
                let htpasswd = htpasswd.clone();
                spawn(move || {
                    let mut request_reader = BufReader::new(downstream.try_clone().unwrap());
                    match Request::read(&mut request_reader) {
                        Ok(Some(mut req)) => {
                            let access_log = match verbosity {
                                v if v >= 1 => AccessLog::new(remote_addr, req_time, &req),
                                _ => AccessLog::Disabled
                            };
                            if req.protocol != "HTTP/1.1" && req.protocol != "HTTP/1.0" {
                                if verbosity >= 2 { eprintln!("Protocol not supported: {}", req.protocol) }
                                return if downstream.write_all(HTTP_VERSION_NOT_SUPPORTED).is_ok() {
                                    access_log.print(505, 0)
                                }
                            }
                            #[cfg(feature = "htpasswd")]
                            if htpasswd.exists() && !req.headers.get_once("Proxy-Authorization").is_some_and(|v| htpasswd.authorize(v)) {
                                return if downstream.write_all(PROXY_AUTHENTICATION_REQUIRED).is_ok() {
                                    access_log.print(407, 0)
                                }
                            }
                            if req.method == "CONNECT" {
                                let host = Host::from(&req.target);
                                let port = match host.port {
                                    Some(port) => port,
                                    _ => {
                                        if verbosity >= 3 { eprintln!("Malformed target: {}", req.target) }
                                        return if downstream.write_all(BAD_REQUEST).is_ok() {
                                            access_log.print(400, 0);
                                        }
                                    }
                                };
                                let addr = match IpAddr::try_from(&host) {
                                    Ok(addr) if !is_forbidden(&addr, forbid_loopback) => addr,
                                    Ok(_) => {
                                        if verbosity >= 3 { eprintln!("Forbidden host: {}", host.name) }
                                        return if downstream.write_all(FORBIDDEN).is_ok() {
                                            access_log.print(403, 0)
                                        }
                                    }
                                    _ if !is_hostname(&host.name) => {
                                        if verbosity >= 3 { eprintln!("Malformed host: {}", host.name) }
                                        return if downstream.write_all(BAD_REQUEST).is_ok() {
                                            access_log.print(400, 0)
                                        }
                                    }
                                    _ => match resolver.resolve(&host.name) {
                                        Ok(addr) if !is_forbidden(&addr, forbid_loopback) => addr,
                                        Ok(_) => {
                                            if verbosity >= 3 { eprintln!("Forbidden host: {}", host.name) }
                                            return if downstream.write_all(FORBIDDEN).is_ok() {
                                                access_log.print(403, 0)
                                            }
                                        }
                                        _ => {
                                            if verbosity >= 1 { eprintln!("Name not resolved: {}", host.name) }
                                            return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                access_log.print(502, 0)
                                            }
                                        }
                                    }
                                };
                                match TcpStream::connect((addr, port)) {
                                    Ok(upstream) => {
                                        match downstream.write_all(b"HTTP/1.1 200 OK\r\n\r\n") {
                                            Ok(_) => access_log.print(200, "-"),
                                            Err(e) => {
                                                if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                return access_log.print(499, "-")
                                            }
                                        }
                                        let mut downstream_reader = downstream.try_clone().unwrap();
                                        let mut downstream_writer = downstream.try_clone().unwrap();
                                        let mut upstream_reader = upstream.try_clone().unwrap();
                                        let mut upstream_writer = upstream.try_clone().unwrap();
                                        let writing_target = req.target.clone();
                                        let upload = spawn(move || {
                                            match copy_all(&mut downstream_reader, &mut upstream_writer) {
                                                Err(Errors::I(e)) if e.kind() == IoErrorKind::ConnectionReset => {
                                                    if verbosity >= 3 { eprintln!("Connection reset from downstream: {}", remote_addr) }
                                                }
                                                Err(Errors::I(e)) => {
                                                    if verbosity >= 2 { eprintln!("Error while reading packets from downstream: {}", remote_addr) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                Err(Errors::O(e)) if e.kind() == IoErrorKind::BrokenPipe => {
                                                    if verbosity >= 3 { eprintln!("Broken pipe to upstream: {}", writing_target) }
                                                }
                                                Err(Errors::O(e)) => {
                                                    if verbosity >= 1 { eprintln!("Error while writing packets to upstream: {}", writing_target) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                _ => {}
                                            }
                                        });
                                        let reading_target = req.target.clone();
                                        let download = spawn(move || {
                                            match copy_all(&mut upstream_reader, &mut downstream_writer) {
                                                Err(Errors::I(e)) if e.kind() == IoErrorKind::ConnectionReset => {
                                                    if verbosity >= 3 { eprintln!("Connection reset from upstream: {}", reading_target) }
                                                }
                                                Err(Errors::I(e)) => {
                                                    if verbosity >= 1 { eprintln!("Error while reading packets from upstream: {}", reading_target) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                Err(Errors::O(e)) if e.kind() == IoErrorKind::BrokenPipe => {
                                                    if verbosity >= 3 { eprintln!("Broken pipe to downstream: {}", remote_addr) }
                                                }
                                                Err(Errors::O(e)) => {
                                                    if verbosity >= 2 { eprintln!("Error while writing packets to downstream: {}", remote_addr) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                _ => {}
                                            }
                                        });
                                        upload.join().unwrap_or_default();
                                        download.join().unwrap_or_default();
                                    }
                                    Err(e) => {
                                        if verbosity >= 1 { eprintln!("Error while connecting to upstream: {}", req.target) }
                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                        return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                            access_log.print(502, 0)
                                        }
                                    }
                                }
                            } else if let Ok(uri) = req.target.parse::<Uri>() {
                                if uri.scheme != "http" {
                                    if verbosity >= 3 { eprintln!("Unsupported scheme: {}", uri.scheme) }
                                    return if downstream.write_all(NOT_IMPLEMENTED).is_ok() {
                                        access_log.print(501, 0)
                                    }
                                }
                                let addr = match IpAddr::try_from(&uri.host) {
                                    Ok(addr) if !is_forbidden(&addr, forbid_loopback) => addr,
                                    Ok(_) => {
                                        if verbosity >= 3 { eprintln!("Forbidden host: {}", uri.host) }
                                        return if downstream.write_all(FORBIDDEN).is_ok() {
                                            access_log.print(403, 0)
                                        }
                                    }
                                    _ if !is_hostname(&uri.host.name) => {
                                        if verbosity >= 3 { eprintln!("Malformed host: {}", uri.host) }
                                        return if downstream.write_all(BAD_REQUEST).is_ok() {
                                            access_log.print(400, 0)
                                        }
                                    }
                                    _ => match resolver.resolve(&uri.host.name) {
                                        Ok(addr) if !is_forbidden(&addr, forbid_loopback) => addr,
                                        Ok(_) => {
                                            if verbosity >= 3 { eprintln!("Forbidden host: {}", uri.host) }
                                            return if downstream.write_all(FORBIDDEN).is_ok() {
                                                access_log.print(403, 0)
                                            }
                                        }
                                        _ => {
                                            if verbosity >= 1 { eprintln!("Name not resolved: {}", uri.host) }
                                            return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                access_log.print(502, 0)
                                            }
                                        }
                                    }
                                };
                                let port = uri.host.port.unwrap_or(80);
                                match TcpStream::connect((addr, port)) {
                                    Ok(mut upstream) => {
                                        req.target = uri.path_and_query.clone();
                                        req.headers.retain(|name, _| !name.to_ascii_lowercase().starts_with("proxy-"));
                                        if let Err(e) = req.write(&mut upstream) {
                                            if verbosity >= 1 { eprintln!("Error while writing headers to upstream: {}", uri.host) }
                                            if verbosity >= 2 { eprintln!("  {:?}", e) }
                                            return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                access_log.print(502, 0)
                                            }
                                        }
                                        if req.headers.contains("Expect", "100-continue") {
                                            let mut response_reader = BufReader::new(upstream.try_clone().unwrap());
                                            match Response::read(&mut response_reader) {
                                                Ok(res) if res.status == 100 => {
                                                    if let Err(e) = res.write(&mut downstream) {
                                                        if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(499, 0)
                                                    }
                                                }
                                                Ok(res) => {
                                                    if res.status < 200 {
                                                        if verbosity >= 1 { eprintln!("Unsupported status: {}", res.status) }
                                                        return if downstream.write_all(NOT_IMPLEMENTED).is_ok() {
                                                            access_log.print(501, 0)
                                                        }
                                                    }
                                                    if let Err(e) = res.write(&mut downstream) {
                                                        if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(499, 0)
                                                    }
                                                    if !res.has_body() {
                                                        return access_log.print(res.status, 0)
                                                    }
                                                    match copy_body(&res.headers, &mut response_reader, &mut downstream) {
                                                        Ok(sent) => {
                                                            return access_log.print(res.status, sent)
                                                        }
                                                        Err(Errors::I(e)) => {
                                                            if verbosity >= 1 { eprintln!("Error while reading body from upstream: {}", uri.host) }
                                                            if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                            return access_log.print(444, "-")
                                                        }
                                                        Err(Errors::O(e)) => {
                                                            if verbosity >= 2 { eprintln!("Error while writing body to downstream: {}", remote_addr) }
                                                            if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                            return access_log.print(499, "-")
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    if verbosity >= 1 { eprintln!("Error while reading headers from upstream: {}", uri.host) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                    return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                        access_log.print(502, 0)
                                                    }
                                                }
                                            }
                                        }
                                        if !matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
                                            match copy_body(&req.headers, &mut request_reader, &mut upstream) {
                                                Err(Errors::I(e)) => {
                                                    if verbosity >= 2 { eprintln!("Error while reading body from downstream: {}", remote_addr) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                    return access_log.print(499, 0)
                                                }
                                                Err(Errors::O(e)) => {
                                                    if verbosity >= 1 { eprintln!("Error while writing body to upstream: {}", uri.host) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                    return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                        access_log.print(502, 0)
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        let mut response_reader = BufReader::new(upstream);
                                        match Response::read(&mut response_reader) {
                                            Ok(mut res) => {
                                                if res.status < 200 {
                                                    if verbosity >= 1 { eprintln!("Unsupported status: {}", res.status) }
                                                    return if downstream.write_all(NOT_IMPLEMENTED).is_ok() {
                                                        access_log.print(501, 0)
                                                    }
                                                }
                                                res.headers.push("Proxy-Connection", "close");
                                                if let Err(e) = res.write(&mut downstream) {
                                                    if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                    return access_log.print(499, 0)
                                                }
                                                if req.method == "HEAD" || !res.has_body() {
                                                    return access_log.print(res.status, 0)
                                                }
                                                match copy_body(&res.headers, &mut response_reader, &mut downstream) {
                                                    Ok(sent) => {
                                                        return access_log.print(res.status, sent)
                                                    }
                                                    Err(Errors::I(e)) => {
                                                        if verbosity >= 1 { eprintln!("Error while reading body from upstream: {}", uri.host) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(444, "-")
                                                    }
                                                    Err(Errors::O(e)) => {
                                                        if verbosity >= 2 { eprintln!("Error while writing body to downstream: {}", remote_addr) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(499, "-")
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                if verbosity >= 1 { eprintln!("Error while reading headers from upstream: {}", uri.host) }
                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                    access_log.print(502, 0)
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if verbosity >= 1 { eprintln!("Error while connecting to upstream: {}", uri.host) }
                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                        return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                            access_log.print(502, 0)
                                        }
                                    }
                                }
                            } else {
                                if verbosity >= 3 { eprintln!("Bad request: {} {} {}", req.method, req.target, req.protocol) }
                                return if downstream.write_all(BAD_REQUEST).is_ok() {
                                    access_log.print(400, 0)
                                }
                            }
                        }
                        Ok(None) => {
                            if verbosity >= 2 { eprintln!("Error while reading headers from downstream: {}", remote_addr) }
                            if verbosity >= 2 { eprintln!("  {:?}", IoError::from(IoErrorKind::UnexpectedEof)) }
                        }
                        Err(e) => {
                            if verbosity >= 2 { eprintln!("Error while reading headers from downstream: {}", remote_addr) }
                            if verbosity >= 2 { eprintln!("  {:?}", e) }
                        }
                    }
                });
            }
            Err(e) => {
                if verbosity >= 1 { eprintln!("TCP incoming error: {:?}", e) }
            }
        }
    })
}
