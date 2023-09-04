use std::collections::HashMap;
use std::env::args;
use std::ffi::{CStr, CString, c_char, c_int, c_long};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::{metadata, read_to_string};
use std::io::{BufRead, BufReader, Error as IOError, ErrorKind, Read, Result as IOResult, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::{sleep, spawn};
use std::time::{Duration, SystemTime};

#[allow(non_camel_case_types)]
type time_t = c_long;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
struct tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

extern "C" {
    fn localtime(time: *const time_t) -> *const tm;
    fn strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const tm) -> usize;
    fn time(time: *mut time_t) -> time_t;
}

enum IOErrors {
    I(IOError),
    O(IOError),
}

struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    fn ensure_line_ending(buf: &[u8]) -> IOResult<()> {
        Ok(if !buf.ends_with(&['\r' as u8, '\n' as u8]) {
            return Err(IOError::new(ErrorKind::InvalidData, "invalid line ending"))
        })
    }

    fn read_request_line<R: BufRead>(reader: &mut R) -> IOResult<(String, String, String)> {
        let mut buf: Vec<u8> = Vec::new();
        let n = reader.read_until('\n' as u8, &mut buf)?;
        Headers::ensure_line_ending(&buf)?;
        let line = String::from_iter(buf[..n-2].iter().map(|c| *c as char));
        let mut i = line.splitn(3, ' ');
        if let (Some(method), Some(target), Some(protocol)) = (i.next(), i.next(), i.next()) {
            return Ok((method.into(), target.into(), protocol.into()))
        }
        Err(IOError::new(ErrorKind::InvalidData, "invalid request line"))
    }

    fn read_status_line<R: BufRead>(reader: &mut R) -> IOResult<(String, u16, String)> {
        let mut buf: Vec<u8> = Vec::new();
        let n = reader.read_until('\n' as u8, &mut buf)?;
        Headers::ensure_line_ending(&buf)?;
        let line = String::from_iter(buf[..n-2].iter().map(|c| *c as char));
        let mut i = line.splitn(3, ' ');
        if let (Some(protocol), Some(status), phrase) = (i.next(), i.next(), i.next()) {
            if let Ok(status) = status.parse() {
                if 200 <= status && status < 600 {
                    return Ok((protocol.into(), status, phrase.unwrap_or_default().into()))
                }
            }
        }
        Err(IOError::new(ErrorKind::InvalidData, "invalid status line"))
    }

    fn read<R: BufRead>(reader: &mut R) -> IOResult<Headers> {
        let mut entries = Vec::new();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.clear();
            let n = reader.read_until('\n' as u8, &mut buf)?;
            Headers::ensure_line_ending(&buf)?;
            if n == 2 { return Ok(Headers { entries }) }
            let line = String::from_iter(buf[..n-2].iter().map(|c| *c as char));
            if let Some((name, value)) = line.split_once(':') {
                entries.push((name.into(), value.trim().into()));
            }
        }
    }

    fn read_request<R: BufRead>(reader: &mut R) -> IOResult<(String, String, String, Headers)> {
        let (method, target, protocol) = Headers::read_request_line(reader)?;
        let headers = Headers::read(reader)?;
        Ok((method, target, protocol, headers))
    }

    fn read_response<R: BufRead>(reader: &mut R) -> IOResult<(String, u16, String, Headers)> {
        let (protocol, status, phrase) = Headers::read_status_line(reader)?;
        let headers = Headers::read(reader)?;
        Ok((protocol, status, phrase, headers))
    }

    fn write_request_line<W: Write>(method: &str, target: &str, protocol: &str, writer: &mut W) -> IOResult<()> {
        let mut buf = Vec::with_capacity(method.len() + 1 + target.len() + 1 + protocol.len() + 2);
        buf.extend(method.chars().map(|c| c as u8).chain([' ' as u8]));
        buf.extend(target.chars().map(|c| c as u8).chain([' ' as u8]));
        buf.extend(protocol.chars().map(|c| c as u8).chain(['\r' as u8, '\n' as u8]));
        writer.write_all(&buf)
    }

    fn write_status_line<W: Write>(protocol: &str, status: u16, phrase: &str, writer: &mut W) -> IOResult<()> {
        assert!(100 <= status && status < 600);
        let mut buf = Vec::with_capacity(protocol.len() + 1 + 3 + 1 + phrase.len() + 2);
        buf.extend(protocol.chars().map(|c| c as u8).chain([' ' as u8]));
        buf.extend(status.to_string().chars().map(|c| c as u8).chain([' ' as u8]));
        buf.extend(phrase.chars().map(|c| c as u8).chain(['\r' as u8, '\n' as u8]));
        writer.write_all(&buf)
    }

    fn get(&self, name: &str) -> Vec<&str> {
        let pat = match name.to_ascii_lowercase().as_str() {
            "cookie" => |c| c == ';',
            "server" => |_| false,
            _ => |c| c == ',',
        };
        self.entries.iter()
            .filter(|e| e.0.eq_ignore_ascii_case(name))
            .map(|e| e.1.as_str())
            .flat_map(|v| v.split(pat).map(|v| v.trim()))
            .collect()
    }

    fn get_once(&self, name: &str) -> Option<&str> {
        let values = self.get(name);
        if values.len() == 1 { Some(&values[0]) } else { None }
    }

    fn get_content_length(&self) -> Option<u64> {
        if let Some(value) = self.get_once("content-length") {
            if let Ok(value) = value.parse() { return Some(value) }
        }
        None
    }

    fn contains(&self, name: &str, value: &str) -> bool {
        self.get(name).iter().any(|v| v.eq_ignore_ascii_case(value))
    }

    fn push(&mut self, name: &str, value: &str) {
        self.entries.push((name.into(), value.into()))
    }

    fn retain<F: Fn(&str, &str) -> bool>(&mut self, f: F) {
        self.entries.retain(|(name, value)| f(&name, &value))
    }

    fn write<W: Write>(&self, writer: &mut W) -> IOResult<()> {
        let mut buf = Vec::new();
        for (name, value) in self.entries.iter() {
            if value.is_empty() { continue }
            buf.extend(name.chars().map(|c| c as u8).chain([':' as u8, ' ' as u8]));
            buf.extend(value.chars().map(|c| c as u8).chain(['\r' as u8, '\n' as u8]));
        }
        buf.extend(['\r' as u8, '\n' as u8]);
        writer.write_all(&buf)
    }

    fn write_request<W: Write>(&self, method: &str, target: &str, protocol: &str, writer: &mut W) -> IOResult<()> {
        Headers::write_request_line(method, target, protocol, writer)?;
        self.write(writer)
    }

    fn write_response<W: Write>(&self, protocol: &str, status: u16, phrase: &str, writer: &mut W) -> IOResult<()> {
        Headers::write_status_line(protocol, status, phrase, writer)?;
        self.write(writer)
    }
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
        s.chars().nth(0).unwrap().is_ascii_alphanumeric() &&
        s.chars().last().unwrap().is_ascii_alphanumeric() &&
        s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn parse_uri(uri: &str) -> Option<(&str, &str, &str)> {
    if let Some((scheme, rest)) = uri.split_once("://") {
        if let Some(sep) = rest.find('/') {
            let (host, path_and_query) = (&rest[..sep], &rest[sep..]);
            return Some((scheme, host, path_and_query))
        }
    }
    None
}

fn parse_host(host: &str) -> (&str, Option<u16>) {
    if let Some((hostname, port)) = host.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return (hostname, Some(port))
        }
    }
    (host, None)
}

fn parse_addr(addr: &str) -> Option<IpAddr> {
    if addr.starts_with('[') && addr.ends_with(']') {
        let addr = &addr[1..addr.len()-1];
        if let Ok(addr) = addr.parse::<Ipv6Addr>() { return Some(addr.into()) }
    } else {
        if let Ok(addr) = addr.parse::<Ipv4Addr>() { return Some(addr.into()) }
    }
    None
}

fn copy<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64, IOErrors> {
    let mut buf = [0; 8192];
    let mut len: u64 = 0;
    loop {
        match reader.read(&mut buf) {
            Ok(n) => {
                if n == 0 { return Ok(len) }
                if let Err(e) = writer.write_all(&buf[..n]) { return Err(IOErrors::O(e)) }
                len += n as u64;
            }
            Err(e) => { return Err(IOErrors::I(e)) }
        }
    }
}

fn copy_exact<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut length: u64) -> Result<(), IOErrors> {
    let mut buf = [0; 8192];
    Ok(while length > 0 {
        let n = length.min(buf.len() as u64) as usize;
        if let Err(e) = reader.read_exact(&mut buf[..n]) { return Err(IOErrors::I(e)) }
        if let Err(e) = writer.write_all(&buf[..n]) { return Err(IOErrors::O(e)) }
        length -= n as u64;
    })
}

fn copy_chunked<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64, IOErrors> {
    let mut buf: Vec<u8> = Vec::new();
    let mut len: u64 = 0;
    loop {
        buf.clear();
        match reader.read_until('\n' as u8, &mut buf) {
            Ok(n) => {
                if let Err(e) = Headers::ensure_line_ending(&buf) { return Err(IOErrors::I(e)) }
                if let Err(e) = writer.write_all(&buf[..n]) { return Err(IOErrors::O(e)) }
                len += n as u64;
                let hex = String::from_iter(buf[..n-2].iter().map(|c| *c as char));
                if let Ok(n) = usize::from_str_radix(&hex, 16) {
                    let n = n + 2;
                    buf.resize(n, 0);
                    match reader.read_exact(&mut buf) {
                        Ok(_) => {
                            if let Err(e) = Headers::ensure_line_ending(&buf) { return Err(IOErrors::I(e)) }
                            if let Err(e) = writer.write_all(&buf[..n]) { return Err(IOErrors::O(e)) }
                        }
                        Err(e) => {
                            return Err(IOErrors::I(e))
                        }
                    }
                    len += n as u64;
                    if n == 2 { return Ok(len) }
                } else {
                    let e = IOError::new(ErrorKind::InvalidData, "invalid chunk length");
                    return Err(IOErrors::I(e))
                }
            }
            Err(e) => {
                return Err(IOErrors::I(e))
            }
        }
    }
}

fn copy_body<R: BufRead, W: Write>(headers: &Headers, reader: &mut R, writer: &mut W) -> Result<u64, IOErrors> {
    if let Some(length) = headers.get_content_length() {
        match copy_exact(reader, writer, length) { Ok(_) => Ok(length), Err(e) => Err(e) }
    } else if headers.contains("Transfer-Encoding", "chunked") {
        copy_chunked(reader, writer)
    } else {
        copy(reader, writer)
    }
}

fn copy_websocket_frames<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<(), IOErrors> {
    loop {
        let mut buf = [0; 2];
        if let Err(e) = reader.read_exact(&mut buf) { return Err(IOErrors::I(e)) }
        if let Err(e) = writer.write_all(&buf) { return Err(IOErrors::O(e)) }
        let opcode = buf[0] & 0x0F;
        let masked = (buf[1] & 0x80) != 0;
        let mut length = (buf[1] & 0x7F) as u64;
        if length == 126 {
            if let Err(e) = reader.read_exact(&mut buf) { return Err(IOErrors::I(e)) }
            if let Err(e) = writer.write_all(&buf) { return Err(IOErrors::O(e)) }
            length = u16::from_be_bytes(buf) as u64;
        }
        if length == 127 {
            let mut buf = [0; 8];
            if let Err(e) = reader.read_exact(&mut buf) { return  Err(IOErrors::I(e)) }
            if let Err(e) = writer.write_all(&buf) { return Err(IOErrors::O(e)) }
            length = u64::from_be_bytes(buf);
        }
        if masked { copy_exact(reader, writer, 4)? }
        copy_exact(reader, writer, length)?;
        if opcode == 8 { return Ok(()) }
    }
}

#[derive(Clone)]
struct Resolver {
    cache: Arc<RwLock<HashMap<String, (IpAddr, SystemTime)>>>,
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    ttl: Duration,
}

impl Resolver {
    fn new(hosts_files: &[String], ttl: Duration) -> Resolver {
        let hosts_files = Arc::new(hosts_files.to_vec());
        let hosts = Arc::new(RwLock::new(HashMap::new()));
        for path in hosts_files.iter() {
            Resolver::parse(&read_to_string(&path).unwrap_or_default(), &mut hosts.write().unwrap())
        }
        let interval = Duration::from_secs(4);
        let hosts_writer = hosts.clone();
        spawn(move || {
            let min_mtime = SystemTime::UNIX_EPOCH;
            let get_mtime = |path: &str| match metadata(path) {
                Ok(m) => m.modified().unwrap(),
                _ => min_mtime,
            };
            let mut lastmtime = hosts_files.iter().fold(min_mtime, |t, p| get_mtime(p).max(t));
            loop {
                sleep(interval);
                let mtime = hosts_files.iter().fold(min_mtime, |t, p| get_mtime(p).max(t));
                if mtime == lastmtime { continue }
                lastmtime = mtime;
                let mut hosts = HashMap::new();
                for path in hosts_files.iter() {
                    Resolver::parse(&read_to_string(path).unwrap_or_default(), &mut hosts)
                }
                let mut writer = hosts_writer.write().unwrap();
                writer.clear();
                for (k, v) in hosts {
                    writer.insert(k, v);
                }
            }
        });
        Resolver { cache: Arc::new(RwLock::new(HashMap::new())), hosts, ttl }
    }

    fn parse(data: &str, hosts: &mut HashMap<String, Vec<IpAddr>>) {
        for line in data.split('\n').filter(|s| s.len() > 0 && !s.starts_with('#')) {
            let mut addr: Option<IpAddr> = None;
            for (i, s) in line.split(char::is_whitespace).filter(|s| s.len() > 0).enumerate() {
                if i == 0 {
                    addr = Some(s.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
                } else if let Some(addr) = addr {
                    hosts.entry(s.to_ascii_lowercase()).or_default().push(addr)
                }
            }
        }
    }

    fn get(&self, hostname: &str) -> Option<IpAddr> {
        let hostname = hostname.to_ascii_lowercase();
        let patterns = match hostname.find('.') {
            Some(dot) => vec![hostname.clone(), format!("*{}", hostname[dot..].to_ascii_lowercase()) ],
            _ => vec![hostname.clone()],
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

    fn resolve(&self, hostname: &str) -> IOResult<IpAddr> {
        if let Some(addr) = self.get(hostname) { return Ok(addr) }
        let now = SystemTime::now();
        if let Some((addr, eol)) = self.cache.read().unwrap().get(hostname) {
            if now < *eol { return Ok(*addr) }
        }
        let addr = format!("{}:0", hostname).to_socket_addrs()?.nth(0).unwrap().ip();
        self.cache.write().unwrap().insert(hostname.into(), (addr, now + self.ttl));
        Ok(addr)
    }
}

struct LocalTime {
    time: time_t,
}

impl LocalTime {
    fn now() -> LocalTime {
        unsafe {
            let mut t = 0;
            time(&mut t);
            LocalTime { time: t }
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

fn main() -> IOResult<()> {
    const BAD_REQUEST: &[u8] = b"\
        HTTP/1.1 400 Bad Request\r\n\
        \r\n";
    const FORBIDDEN: &[u8] = b"\
        HTTP/1.1 403 Forbidden\r\n\
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
        let mut i = args().skip(1);
        while let Some(k) = i.next() {
            match k.as_str() {
                "-h" | "--help"      => print_help_and_exit(0),
                "-s" | "--silent"    => verbosity -= 1,
                "-v" | "--verbose"   => verbosity += 1,
                "-vv"                => verbosity += 2,
                "-4" | "--ipv4-only" => ipv4only = true,
                "-H" | "--hosts" => match i.next() {
                    Some(v) => hosts.push(v),
                    _ => print_help_and_exit(1)
                }
                "-p" | "--port" => match i.next() {
                    Some(v) => match v.parse() {
                        Ok(v) => port = v,
                        _ => print_help_and_exit(1)
                    }
                    _ => print_help_and_exit(1)
                }
                _ => print_help_and_exit(1)
            }
        }
        (verbosity, ipv4only, hosts, port)
    };
    let resolver = Resolver::new(&hosts_files, Duration::from_secs(120));

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
                spawn(move || {
                    let mut request_reader = BufReader::new(&mut downstream);
                    match Headers::read_request(&mut request_reader) {
                        Ok((method, target, protocol, mut headers)) => {
                            let log = |status: u16, sent: Option<u64>| {
                                let sent = if let Some(sent) = sent { sent.to_string() } else { "-".into() };
                                println!("{} - - [{}] \"{} {} {}\" {} {}",
                                    &remote_addr, &request_time, &method, &target, &protocol, status, &sent);
                            };
                            if protocol != "HTTP/1.1" && protocol != "HTTP/1.0" {
                                if verbosity >= 2 { eprintln!("Protocol not supported: {}", protocol) }
                                if verbosity >= 1 { log(505, Some(0)) }
                                return downstream.write_all(HTTP_VERSION_NOT_SUPPORTED).unwrap_or_default()
                            }
                            if method == "CONNECT" {
                                let (hostname, port) = match parse_host(&target) {
                                    (hostname, Some(port)) => (hostname, port),
                                    _ => {
                                        if verbosity >= 3 { eprintln!("Malformed target: {}", target) }
                                        if verbosity >= 1 { log(400, Some(0)) }
                                        return downstream.write_all(BAD_REQUEST).unwrap_or_default()
                                    }
                                };
                                if hostname.eq_ignore_ascii_case("localhost") {
                                    if verbosity >= 3 { eprintln!("Forbidden host: {}", hostname) }
                                    if verbosity >= 1 { log(403, Some(0)) }
                                    return downstream.write_all(FORBIDDEN).unwrap_or_default()
                                }
                                let addr = match parse_addr(hostname) {
                                    Some(addr) if !is_forbidden(&addr) => addr,
                                    Some(_) => {
                                        if verbosity >= 3 { eprintln!("Forbidden host: {}", hostname) }
                                        if verbosity >= 1 { log(403, Some(0)) }
                                        return downstream.write_all(FORBIDDEN).unwrap_or_default()
                                    }
                                    _ if !is_hostname(hostname) => {
                                        if verbosity >= 3 { eprintln!("Malformed host: {}", hostname) }
                                        if verbosity >= 1 { log(400, Some(0)) }
                                        return downstream.write_all(BAD_REQUEST).unwrap_or_default()
                                    }
                                    _ => match resolver.resolve(hostname) {
                                        Ok(addr) if !is_forbidden(&addr) => addr,
                                        Ok(_) => {
                                            if verbosity >= 3 { eprintln!("Forbidden host: {}", hostname) }
                                            if verbosity >= 1 { log(403, Some(0)) }
                                            return downstream.write_all(FORBIDDEN).unwrap_or_default()
                                        }
                                        _ => {
                                            if verbosity >= 1 { eprintln!("Name not resolved: {}", hostname) }
                                            if verbosity >= 1 { log(502, Some(0)) }
                                            return downstream.write_all(BAD_GATEWAY).unwrap_or_default();
                                        }
                                    }
                                };
                                match TcpStream::connect((addr, port)) {
                                    Ok(upstream) => {
                                        downstream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap_or_default();
                                        if verbosity >= 1 { log(200, None) }
                                        let mut downstream_reader = downstream.try_clone().unwrap();
                                        let mut downstream_writer = downstream.try_clone().unwrap();
                                        let mut upstream_reader = upstream.try_clone().unwrap();
                                        let mut upstream_writer = upstream.try_clone().unwrap();
                                        let writing_target = target.clone();
                                        let upload = spawn(move || {
                                            match copy(&mut downstream_reader, &mut upstream_writer) {
                                                Err(IOErrors::I(e)) => {
                                                    if verbosity >= 2 { eprintln!("Error while reading packets from downstream: {}", remote_addr) }
                                                    if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                }
                                                Err(IOErrors::O(e)) => {
                                                    if verbosity >= 1 { eprintln!("Error while writing packets to upstream: {}", writing_target) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                _ => {}
                                            }
                                        });
                                        let reading_target = target.clone();
                                        let download = spawn(move || {
                                            match copy(&mut upstream_reader, &mut downstream_writer) {
                                                Err(IOErrors::I(e)) if e.kind() != ErrorKind::ConnectionReset => {
                                                    if verbosity >= 2 { eprintln!("Connection reset from upstream: {}", reading_target) }
                                                }
                                                Err(IOErrors::I(e)) => {
                                                    if verbosity >= 1 { eprintln!("Error while reading packets from upstream: {}", reading_target) }
                                                    if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                }
                                                Err(IOErrors::O(e)) => {
                                                    if verbosity >= 2 { eprintln!("Error while writing packets to downstream: {}", remote_addr) }
                                                    if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                }
                                                _ => {}
                                            }
                                        });
                                        upload.join().unwrap_or_default();
                                        download.join().unwrap_or_default();
                                    }
                                    Err(e) => {
                                        if verbosity >= 1 { eprintln!("Error while connecting to upstream: {}", target) }
                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                        if verbosity >= 1 { log(502, Some(0)) }
                                        return downstream.write_all(BAD_GATEWAY).unwrap_or_default();
                                    }
                                }
                            } else if let Some((scheme, host, target)) = parse_uri(&target) {
                                if scheme != "http" {
                                    if verbosity >= 3 { eprintln!("Unsupported scheme: {}", scheme) }
                                    if verbosity >= 1 { log(501, Some(0)) }
                                    return downstream.write_all(NOT_IMPLEMENTED).unwrap_or_default()
                                }
                                let (hostname, port) = parse_host(host);
                                let port = port.unwrap_or(80);
                                if hostname.eq_ignore_ascii_case("localhost") {
                                    if verbosity >= 3 { eprintln!("Forbidden host: {}", hostname) }
                                    if verbosity >= 1 { log(403, Some(0)) }
                                    return downstream.write_all(FORBIDDEN).unwrap_or_default()
                                }
                                let addr = match parse_addr(hostname) {
                                    Some(addr) if !is_forbidden(&addr) => addr,
                                    Some(_) => {
                                        if verbosity >= 3 { eprintln!("Forbidden host: {}", hostname) }
                                        if verbosity >= 1 { log(403, Some(0)) }
                                        return downstream.write_all(FORBIDDEN).unwrap_or_default()
                                    }
                                    _ if !is_hostname(hostname) => {
                                        if verbosity >= 3 { eprintln!("Malformed host: {}", hostname) }
                                        if verbosity >= 1 { log(400, Some(0)) }
                                        return downstream.write_all(BAD_REQUEST).unwrap_or_default()
                                    }
                                    _ => match resolver.resolve(hostname) {
                                        Ok(addr) if !is_forbidden(&addr) => addr,
                                        Ok(_) => {
                                            if verbosity >= 3 { eprintln!("Forbidden host: {}", hostname) }
                                            if verbosity >= 1 { log(403, Some(0)) }
                                            return downstream.write_all(FORBIDDEN).unwrap_or_default()
                                        }
                                        _ => {
                                            if verbosity >= 1 { eprintln!("Name not resolved: {}", hostname) }
                                            if verbosity >= 1 { log(502, Some(0)) }
                                            return downstream.write_all(BAD_GATEWAY).unwrap_or_default();
                                        }
                                    }
                                };
                                let is_websocket_request = method == "GET"
                                    && headers.contains("Connection", "upgrade")
                                    && headers.contains("Upgrade", "websocket")
                                    && headers.contains("Sec-WebSocket-Version", "13");
                                if headers.contains("Sec-WebSocket-Extensions", "permessage-deflate") {
                                    if verbosity >= 1 { eprintln!("Unsupported WebSocket extension: {}", "permessage-deflate") }
                                    if verbosity >= 1 { log(501, Some(0)) }
                                    return downstream.write_all(NOT_IMPLEMENTED).unwrap_or_default()
                                }
                                headers.retain(|name, _| !name.to_ascii_lowercase().starts_with("proxy-"));
                                match TcpStream::connect((addr, port)) {
                                    Ok(mut upstream) => {
                                        let mut buf = Vec::new();
                                        headers.write_request(&method, &target, &protocol, &mut buf).unwrap();
                                        if let Err(e) = upstream.write_all(&buf) {
                                            if verbosity >= 1 { eprintln!("Error while writing headers to upstream: {}", host) }
                                            if verbosity >= 2 { eprintln!("  {:?}", e) }
                                            if verbosity >= 1 { log(502, Some(0)) }
                                            return downstream.write_all(BAD_GATEWAY).unwrap_or_default()
                                        }
                                        match method.as_str() {
                                            "GET" | "HEAD" | "OPTIONS" => {}
                                            _ => {
                                                match copy_body(&headers, &mut request_reader, &mut upstream) {
                                                    Err(IOErrors::I(e)) => {
                                                        if verbosity >= 2 { eprintln!("Error while reading body from downstream: {}", remote_addr) }
                                                        if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                        return if verbosity >= 1 { log(499, Some(0)) }
                                                    }
                                                    Err(IOErrors::O(e)) => {
                                                        if verbosity >= 1 { eprintln!("Error while writing body to upstream: {}", host) }
                                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                        if verbosity >= 1 { log(502, Some(0)) }
                                                        return downstream.write_all(BAD_GATEWAY).unwrap_or_default()
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        let mut response_reader = BufReader::new(&mut upstream);
                                        match Headers::read_response(&mut response_reader) {
                                            Ok((protocol, status, phrase, mut headers)) => {
                                                let is_upgradable = headers.contains("Connection", "upgrade")
                                                    && headers.get_content_length().unwrap_or_default() == 0
                                                    && !headers.contains("Transfer-Encoding", "chunked");
                                                let is_websocket_response = status == 101
                                                    && headers.contains("Connection", "upgrade")
                                                    && headers.contains("Upgrade", "websocket");
                                                if status < 200 && !(is_upgradable && is_websocket_request && is_websocket_response) {
                                                    if verbosity >= 1 { eprintln!("Unsupported status: {}", status) }
                                                    if verbosity >= 1 { log(501, Some(0)) }
                                                    return downstream.write_all(NOT_IMPLEMENTED).unwrap_or_default()
                                                }
                                                headers.push("Proxy-Connection", "close");
                                                let mut buf = Vec::new();
                                                headers.write_response(&protocol, status, &phrase, &mut buf).unwrap();
                                                if let Err(e) = downstream.write_all(&buf) {
                                                    if verbosity >= 2 { eprintln!("Error while writing headers to downstream: {}", remote_addr) }
                                                    if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                    return if verbosity >= 1 { log(499, Some(0)) }
                                                }
                                                if method == "HEAD" || !is_websocket_response && status < 200 || status == 204 || status == 304 {
                                                    if verbosity >= 1 { log(status, Some(0)) }
                                                } else {
                                                    match copy_body(&headers, &mut response_reader, &mut downstream) {
                                                        Ok(sent) => {
                                                            if verbosity >= 1 { log(status, Some(sent)) }
                                                        }
                                                        Err(IOErrors::I(e)) => {
                                                            if verbosity >= 1 { eprintln!("Error while reading body from upstream: {}", host) }
                                                            if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                            return if verbosity >= 1 { log(444, None) }
                                                        }
                                                        Err(IOErrors::O(e)) => {
                                                            if verbosity >= 2 { eprintln!("Error while writing body to downstream: {}", remote_addr) }
                                                            if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                            return if verbosity >= 1 { log(499, None) }
                                                        }
                                                    }
                                                }
                                                if is_websocket_response {
                                                    if verbosity >= 1 { log(status, None) }
                                                    let mut downstream_reader = downstream.try_clone().unwrap();
                                                    let mut downstream_writer = downstream.try_clone().unwrap();
                                                    let mut upstream_reader = upstream.try_clone().unwrap();
                                                    let mut upstream_writer = upstream.try_clone().unwrap();
                                                    let writing_host = host.to_string();
                                                    let upload = spawn(move || {
                                                        match copy_websocket_frames(&mut downstream_reader, &mut upstream_writer) {
                                                            Err(IOErrors::I(e)) => {
                                                                if verbosity >= 2 { eprintln!("Error while reading frames from downstream: {}", remote_addr) }
                                                                if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                            }
                                                            Err(IOErrors::O(e)) => {
                                                                if verbosity >= 1 { eprintln!("Error while writing frames to upstream: {}", writing_host) }
                                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                            }
                                                            _ => {}
                                                        }
                                                    });
                                                    let reading_host = host.to_string();
                                                    let download = spawn(move || {
                                                        match copy_websocket_frames(&mut upstream_reader, &mut downstream_writer) {
                                                            Err(IOErrors::I(e)) => {
                                                                if verbosity >= 1 { eprintln!("Error while reading frames from upstream: {}", reading_host) }
                                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                            }
                                                            Err(IOErrors::O(e)) => {
                                                                if verbosity >= 2 { eprintln!("Error while writing frames to downstream: {}", remote_addr) }
                                                                if verbosity >= 3 { eprintln!("  {:?}", e) }
                                                            }
                                                            _ => {}
                                                        }
                                                    });
                                                    upload.join().unwrap_or_default();
                                                    download.join().unwrap_or_default();
                                                }
                                            }
                                            Err(e) => {
                                                if verbosity >= 1 { eprintln!("Error while reading headers from upstream: {}", host) }
                                                if verbosity >= 2 { eprintln!("  {:?}", e) }
                                                if verbosity >= 1 { log(502, Some(0)) }
                                                return downstream.write_all(BAD_GATEWAY).unwrap_or_default();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if verbosity >= 1 { eprintln!("Error while connecting to upstream: {}", host) }
                                        if verbosity >= 2 { eprintln!("  {:?}", e) }
                                        if verbosity >= 1 { log(502, Some(0)) }
                                        return downstream.write_all(BAD_GATEWAY).unwrap_or_default();
                                    }
                                }
                            } else {
                                if verbosity >= 3 { eprintln!("Bad request: {} {} {}", method, target, protocol) }
                                if verbosity >= 1 { log(400, Some(0)) }
                                return downstream.write_all(BAD_REQUEST).unwrap_or_default()
                            }
                        }
                        Err(e) => {
                            if verbosity >= 2 { eprintln!("Error while reading headers from downstream: {}", remote_addr) }
                            if verbosity >= 3 { eprintln!("  {:?}", e) }
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
