use std::collections::HashMap;
use std::env::args;
use std::ffi::{CStr, CString, c_char, c_int, c_long};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::{metadata, read_to_string};
use std::io::{BufRead, BufReader, Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
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

#[allow(non_camel_case_types)]
type time_t = c_long;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct tm {
    tm_sec   : c_int,
    tm_min   : c_int,
    tm_hour  : c_int,
    tm_mday  : c_int,
    tm_mon   : c_int,
    tm_year  : c_int,
    tm_wday  : c_int,
    tm_yday  : c_int,
    tm_isdst : c_int,
    tm_gmtoff: c_long,
    tm_zone  : *const c_char,
}

extern "C" {
    fn localtime(time: *const time_t) -> *const tm;
    fn strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const tm) -> usize;
    fn time(time: *mut time_t) -> time_t;
}

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

fn is_forbidden(addr: &IpAddr) -> bool {
    let addr = unmap_ipv4_in_ipv6(addr);
    addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() || match addr {
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
    let mut buf: Vec<u8> = Vec::new();
    let mut len: u64 = 0;
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(n) => {
                if !buf.ends_with(b"\r\n") { return Err(Errors::I(ErrorKind::InvalidData.into())) }
                if let Err(e) = writer.write_all(&buf[..n]) { return Err(Errors::O(e)) }
                len += n as u64;
                let hex = String::from_iter(buf[..n-2].iter().map(|c| *c as char));
                if let Ok(n) = usize::from_str_radix(&hex, 16) {
                    let n = n + 2;
                    buf.resize(n, 0);
                    match reader.read_exact(&mut buf) {
                        Ok(_) => {
                            if !buf.ends_with(b"\r\n") { return Err(Errors::I(ErrorKind::InvalidData.into())) }
                            if let Err(e) = writer.write_all(&buf[..n]) { return Err(Errors::O(e)) }
                        }
                        Err(e) => {
                            return Err(Errors::I(e))
                        }
                    }
                    len += n as u64;
                    if n == 2 { return Ok(len) }
                } else {
                    return Err(Errors::I(ErrorKind::InvalidData.into()))
                }
            }
            Err(e) => {
                return Err(Errors::I(e))
            }
        }
    }
}

fn copy_body<R: BufRead, W: Write>(headers: &Headers, reader: &mut R, writer: &mut W) -> Result<u64, Errors> {
    if let Some(len) = headers.get_content_length() {
        match copy_exact(reader, writer, len) { Ok(_) => Ok(len), Err(e) => Err(e) }
    } else if headers.contains("Transfer-Encoding", "chunked") {
        copy_chunked(reader, writer)
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
        let hostname = hostname.to_ascii_lowercase();
        let patterns = match hostname.find('.') {
            Some(dot) => vec![hostname.clone(), format!("*{}", &hostname[dot..])],
            None => vec![hostname.clone()],
        };
        let hosts = self.hosts.read().unwrap();
        if let Some(addrs) = patterns.iter().find_map(|pat| hosts.get(pat)) {
            return Some(addrs[0])
        }
        if let Some((_, addrs)) = hosts.iter().find(|(pat, _)| {
            pat.starts_with("**.") && (hostname == &pat[3..] || hostname.ends_with(&pat[2..]))
        }) {
            return Some(addrs[0])
        }
        None
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct LocalTime {
    time: time_t,
}

impl LocalTime {
    fn now() -> Self {
        unsafe {
            let mut t = 0;
            time(&mut t);
            Self { time: t }
        }
    }
}

impl Display for LocalTime {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        unsafe {
            let fmt = CString::new("%d/%b/%Y:%H:%M:%S %z").unwrap();
            let tm = localtime(&self.time);
            let mut s: [c_char; 32] = [0; 32];
            strftime(s.as_mut_ptr(), s.len(), fmt.as_ptr(), tm);
            write!(f, "{}", CStr::from_ptr(s.as_ptr()).to_str().unwrap())
        }
    }
}

struct RequestInfo {
    remote_addr: IpAddr,
    request_time: LocalTime,
    method: String,
    target: String,
    protocol: String,
}

enum AccessLog {
    Enabled(RequestInfo),
    Disabled,
}

impl AccessLog {
    fn new(remote_addr: IpAddr, request_time: LocalTime, request: &Request) -> Self {
        Self::Enabled(RequestInfo {
            remote_addr,
            request_time,
            method: request.method.clone(),
            target: request.target.clone(),
            protocol: request.protocol.clone(),
        })
    }

    fn print(&self, status: u16, sent: Option<u64>) {
        match self {
            Self::Enabled(info) => {
                let sent = if let Some(sent) = sent { sent.to_string() } else { "-".into() };
                println!("{} - - [{}] \"{} {} {}\" {} {}",
                    info.remote_addr, info.request_time, info.method, info.target, info.protocol, status, sent);
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
        eprintln!("  -4, --ipv4-only      Do not listen on IPv6");
        eprintln!("  -H, --hosts <path>   Hosts files to be read in addition to /etc/hosts");
        eprintln!("  -p, --port <number>  Listen on port (default: 8080)");
        exit(code)
    };
    let (verbosity, ipv4only, hosts_files, port) = {
        let mut verbosity = 1;
        let mut ipv4only = false;
        let mut hosts = vec!["/etc/hosts".into()];
        let mut port = 8080;
        let mut iter = args().skip(1);
        while let Some(k) = iter.next() {
            match k.as_str() {
                "-h" | "--help"      => print_help_and_exit(0),
                "-s" | "--silent"    => verbosity -= 1,
                "-v" | "--verbose"   => verbosity += 1,
                "-vv"                => verbosity += 2,
                "-4" | "--ipv4-only" => ipv4only = true,
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
        (verbosity, ipv4only, hosts, port)
    };
    let resolver = Resolver::new(hosts_files, Duration::from_secs(120));
    #[cfg(feature = "htpasswd")]
    let htpasswd = Htpasswd::new();

    let listener = TcpListener::bind(if ipv4only {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
    })?;
    Ok(for incoming in listener.incoming() {
        match incoming {
            Ok(mut downstream) => {
                let remote_addr = unmap_ipv4_in_ipv6(&downstream.peer_addr().unwrap().ip());
                let request_time = LocalTime::now();
                let resolver = resolver.clone();
                #[cfg(feature = "htpasswd")]
                let htpasswd = htpasswd.clone();
                spawn(move || {
                    let mut request_reader = BufReader::new(&mut downstream);
                    match Request::read(&mut request_reader) {
                        Ok(Some(mut req)) => {
                            let access_log = match verbosity {
                                v if v >= 1 => AccessLog::new(remote_addr, request_time, &req),
                                _ => AccessLog::Disabled
                            };
                            if req.protocol != "HTTP/1.1" && req.protocol != "HTTP/1.0" {
                                if verbosity >= 2 { eprintln!("Protocol not supported: {}", req.protocol) }
                                return if downstream.write_all(HTTP_VERSION_NOT_SUPPORTED).is_ok() {
                                    access_log.print(505, Some(0))
                                }
                            }
                            #[cfg(feature = "htpasswd")]
                            if htpasswd.exists() && !req.headers.get_once("Proxy-Authorization").is_some_and(|v| htpasswd.authorize(v)) {
                                return if downstream.write_all(PROXY_AUTHENTICATION_REQUIRED).is_ok() {
                                    access_log.print(407, Some(0))
                                }
                            }
                            if req.method == "CONNECT" {
                                let host = Host::parse(&req.target);
                                let port = match host.port {
                                    Some(port) => port,
                                    _ => {
                                        if verbosity >= 3 { eprintln!("Malformed target: {}", req.target) }
                                        return if downstream.write_all(BAD_REQUEST).is_ok() {
                                            access_log.print(400, Some(0));
                                        }
                                    }
                                };
                                if host.name.eq_ignore_ascii_case("localhost") {
                                    if verbosity >= 3 { eprintln!("Forbidden host: {}", host.name) }
                                    return if downstream.write_all(FORBIDDEN).is_ok() {
                                        access_log.print(403, Some(0))
                                    }
                                }
                                let addr = match host.to_addr() {
                                    Ok(addr) if !is_forbidden(&addr) => addr,
                                    Ok(_) => {
                                        if verbosity >= 3 { eprintln!("Forbidden host: {}", host.name) }
                                        return if downstream.write_all(FORBIDDEN).is_ok() {
                                            access_log.print(403, Some(0))
                                        }
                                    }
                                    _ if !is_hostname(&host.name) => {
                                        if verbosity >= 3 { eprintln!("Malformed host: {}", host.name) }
                                        return if downstream.write_all(BAD_REQUEST).is_ok() {
                                            access_log.print(400, Some(0))
                                        }
                                    }
                                    _ => match resolver.resolve(&host.name) {
                                        Ok(addr) if !is_forbidden(&addr) => addr,
                                        Ok(_) => {
                                            if verbosity >= 3 { eprintln!("Forbidden host: {}", host.name) }
                                            return if downstream.write_all(FORBIDDEN).is_ok() {
                                                access_log.print(403, Some(0))
                                            }
                                        }
                                        _ => {
                                            if verbosity >= 1 { eprintln!("Name not resolved: {}", host.name) }
                                            return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                access_log.print(502, Some(0))
                                            }
                                        }
                                    }
                                };
                                match TcpStream::connect((addr, port)) {
                                    Ok(upstream) => {
                                        match downstream.write_all(b"HTTP/1.1 200 OK\r\n\r\n") {
                                            Ok(_) => access_log.print(200, None),
                                            Err(e) => {
                                                if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                return access_log.print(499, None)
                                            }
                                        }
                                        let mut downstream_reader = downstream.try_clone().unwrap();
                                        let mut downstream_writer = downstream.try_clone().unwrap();
                                        let mut upstream_reader = upstream.try_clone().unwrap();
                                        let mut upstream_writer = upstream.try_clone().unwrap();
                                        let writing_target = req.target.clone();
                                        let upload = spawn(move || {
                                            match copy_all(&mut downstream_reader, &mut upstream_writer) {
                                                Err(Errors::I(e)) if e.kind() == ErrorKind::ConnectionReset => {
                                                    if verbosity >= 3 { eprintln!("Connection reset from downstream: {}", remote_addr) }
                                                }
                                                Err(Errors::I(e)) => {
                                                    if verbosity >= 2 { eprintln!("Error while reading packets from downstream: {}", remote_addr) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                Err(Errors::O(e)) if e.kind() == ErrorKind::BrokenPipe => {
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
                                                Err(Errors::I(e)) if e.kind() == ErrorKind::ConnectionReset => {
                                                    if verbosity >= 3 { eprintln!("Connection reset from upstream: {}", reading_target) }
                                                }
                                                Err(Errors::I(e)) => {
                                                    if verbosity >= 1 { eprintln!("Error while reading packets from upstream: {}", reading_target) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                Err(Errors::O(e)) if e.kind() == ErrorKind::BrokenPipe => {
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
                                            access_log.print(502, Some(0))
                                        }
                                    }
                                }
                            } else if let Some(uri) = Uri::parse(&req.target) {
                                if uri.scheme != "http" {
                                    if verbosity >= 3 { eprintln!("Unsupported scheme: {}", uri.scheme) }
                                    return if downstream.write_all(NOT_IMPLEMENTED).is_ok() {
                                        access_log.print(501, Some(0))
                                    }
                                }
                                if uri.host.name.eq_ignore_ascii_case("localhost") {
                                    if verbosity >= 3 { eprintln!("Forbidden host: {}", uri.host) }
                                    return if downstream.write_all(FORBIDDEN).is_ok() {
                                        access_log.print(403, Some(0))
                                    }
                                }
                                let addr = match uri.host.to_addr() {
                                    Ok(addr) if !is_forbidden(&addr) => addr,
                                    Ok(_) => {
                                        if verbosity >= 3 { eprintln!("Forbidden host: {}", uri.host) }
                                        return if downstream.write_all(FORBIDDEN).is_ok() {
                                            access_log.print(403, Some(0))
                                        }
                                    }
                                    _ if !is_hostname(&uri.host.name) => {
                                        if verbosity >= 3 { eprintln!("Malformed host: {}", uri.host) }
                                        return if downstream.write_all(BAD_REQUEST).is_ok() {
                                            access_log.print(400, Some(0))
                                        }
                                    }
                                    _ => match resolver.resolve(&uri.host.name) {
                                        Ok(addr) if !is_forbidden(&addr) => addr,
                                        Ok(_) => {
                                            if verbosity >= 3 { eprintln!("Forbidden host: {}", uri.host) }
                                            return if downstream.write_all(FORBIDDEN).is_ok() {
                                                access_log.print(403, Some(0))
                                            }
                                        }
                                        _ => {
                                            if verbosity >= 1 { eprintln!("Name not resolved: {}", uri.host) }
                                            return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                access_log.print(502, Some(0))
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
                                                access_log.print(502, Some(0))
                                            }
                                        }
                                        match req.method.as_str() {
                                            "GET" | "HEAD" | "OPTIONS" => {}
                                            _ => {
                                                match copy_body(&req.headers, &mut request_reader, &mut upstream) {
                                                    Err(Errors::I(e)) => {
                                                        if verbosity >= 2 { eprintln!("Error while reading body from downstream: {}", remote_addr) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(499, Some(0))
                                                    }
                                                    Err(Errors::O(e)) => {
                                                        if verbosity >= 1 { eprintln!("Error while writing body to upstream: {}", uri.host) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                            access_log.print(502, Some(0))
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        let mut response_reader = BufReader::new(&mut upstream);
                                        match Response::read(&mut response_reader) {
                                            Ok(mut res) => {
                                                if res.status < 200 {
                                                    if verbosity >= 1 { eprintln!("Unsupported status: {}", res.status) }
                                                    return if downstream.write_all(NOT_IMPLEMENTED).is_ok() {
                                                        access_log.print(501, Some(0))
                                                    }
                                                }
                                                res.headers.push("Proxy-Connection", "close");
                                                if let Err(e) = res.write(&mut downstream) {
                                                    if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                    return access_log.print(499, Some(0))
                                                }
                                                if req.method == "HEAD" || !res.has_body() {
                                                    return access_log.print(res.status, Some(0))
                                                }
                                                match copy_body(&res.headers, &mut response_reader, &mut downstream) {
                                                    Ok(sent) => {
                                                        return access_log.print(res.status, Some(sent))
                                                    }
                                                    Err(Errors::I(e)) => {
                                                        if verbosity >= 1 { eprintln!("Error while reading body from upstream: {}", uri.host) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(444, None)
                                                    }
                                                    Err(Errors::O(e)) => {
                                                        if verbosity >= 2 { eprintln!("Error while writing body to downstream: {}", remote_addr) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        return access_log.print(499, None)
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                if verbosity >= 1 { eprintln!("Error while reading headers from upstream: {}", uri.host) }
                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                                    access_log.print(502, Some(0))
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if verbosity >= 1 { eprintln!("Error while connecting to upstream: {}", uri.host) }
                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                        return if downstream.write_all(BAD_GATEWAY).is_ok() {
                                            access_log.print(502, Some(0))
                                        }
                                    }
                                }
                            } else {
                                if verbosity >= 3 { eprintln!("Bad request: {} {} {}", req.method, req.target, req.protocol) }
                                return if downstream.write_all(BAD_REQUEST).is_ok() {
                                    access_log.print(400, Some(0))
                                }
                            }
                        }
                        Ok(None) => {
                            if verbosity >= 2 { eprintln!("Error while reading headers from downstream: {}", remote_addr) }
                            if verbosity >= 2 { eprintln!("  {:?}", IoError::from(ErrorKind::UnexpectedEof)) }
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
