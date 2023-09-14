use std::borrow::Cow;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{BufRead, Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriKind {
    Absolute,
}

#[derive(Clone, Debug)]
pub struct Headers {
    entries: Vec<(Cow<'static, str>, Cow<'static, str>)>,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub protocol: String,
    pub headers: Headers,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub protocol: String,
    pub status: u16,
    pub phrase: String,
    pub headers: Headers,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uri {
    pub scheme: String,
    pub host: Host,
    pub path_and_query: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UriParseError(UriKind);

fn decode(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len());
    s.extend(buf.iter().map(|x| *x as char));
    s
}

fn encode(s: &str, buf: &mut Vec<u8>) {
    assert!(s.chars().all(|c| c <= '\u{FF}'));
    buf.reserve(s.len());
    buf.extend(s.chars().map(|c| c as u8))
}

fn parse(buf: &[u8]) -> Option<usize> {
    let mut value = 0;
    for c in buf.iter() {
        if *c < b'0' || b'9' < *c { return None }
        value = value * 10 + (*c - b'0') as usize;
    }
    Some(value)
}

fn trim_start(buf: &[u8]) -> &[u8] {
    &buf[buf.iter().take_while(|c| (**c as char).is_ascii_whitespace()).count()..]
}

fn read_line<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> IoResult<Option<usize>> {
    match reader.read_until(b'\n', buf)? {
        0 => Ok(None),
        n if buf.ends_with(b"\r\n") => Ok(Some(n - 2)),
        _ => Err(IoError::new(IoErrorKind::InvalidData, "invalid line ending"))
    }
}

impl Headers {
    fn value_separator(name: &str) -> fn(char) -> bool {
        if name.eq_ignore_ascii_case("Cookie") { return |c| c == ';' }
        if name.eq_ignore_ascii_case("Server") { return |_| false }
        |c| c == ','
    }

    pub fn contains_any<F: Fn(&str) -> bool>(&self, name: &str, f: F) -> bool {
        let pat = Self::value_separator(name);
        self.entries.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(pat).map(|v| v.trim()))
            .any(f)
    }

    pub fn contains(&self, name: &str, value: &str) -> bool {
        self.contains_any(name, |v| v.eq_ignore_ascii_case(value))
    }

    #[allow(dead_code)]
    pub fn get_once(&self, name: &str) -> Option<&str> {
        let pat = Self::value_separator(name);
        let mut iter = self.entries.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(pat).map(|v| v.trim()));
        match (iter.next(), iter.next()) { (Some(value), None) => Some(value), _ => None }
    }

    pub fn get_last(&self, name: &str) -> Option<&str> {
        let pat = Self::value_separator(name);
        self.entries.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(pat).map(|v| v.trim()))
            .last()
    }

    pub fn get_content_length(&self) -> Option<u64> {
        self.get_last("Content-Length").and_then(|v| v.parse().ok())
    }

    pub fn push<N: Into<Cow<'static, str>>, V: Into<Cow<'static, str>>>(&mut self, name: N, value: V) {
        self.entries.push((name.into(), value.into()))
    }

    pub fn retain<F: Fn(&str, &str) -> bool>(&mut self, f: F) {
        self.entries.retain(|(name, value)| f(&name, &value))
    }

    fn read<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> IoResult<Self> {
        let mut entries = Vec::new();
        loop {
            buf.clear();
            match read_line(reader, buf)? {
                None => return Err(IoError::from(IoErrorKind::UnexpectedEof)),
                Some(n) if n == 0 => return Ok(Self { entries }),
                Some(n) => {
                    let mut iter = (&buf[..n]).splitn(2, |c| *c == b':');
                    if let (Some(name), Some(value)) = (iter.next(), iter.next()) {
                        entries.push((decode(name).into(), decode(trim_start(value)).into()))
                    }
                }
            }
        }
    }

    fn write(&self, buf: &mut Vec<u8>) {
        for (name, value) in self.entries.iter() {
            encode(name, buf);
            buf.extend_from_slice(b": ");
            encode(value, buf);
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"\r\n");
    }
}

impl Request {
    pub fn read<R: BufRead>(reader: &mut R) -> IoResult<Option<Self>> {
        let mut buf = Vec::with_capacity(8192);
        match read_line(reader, &mut buf)? {
            None => Ok(None),
            Some(n) => {
                let mut iter = (&buf[..n]).splitn(3, |c| *c == b' ');
                match (iter.next(), iter.next(), iter.next()) {
                    (Some(method), Some(target), Some(protocol)) => Ok(Some(Self {
                        method: decode(method),
                        target: decode(target),
                        protocol: decode(protocol),
                        headers: Headers::read(reader, &mut buf)?
                    })),
                    _ => Err(IoError::new(IoErrorKind::InvalidData, "invalid request line"))
                }
            }
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        let mut buf = Vec::with_capacity(8192);
        encode(&self.method, &mut buf);
        buf.extend_from_slice(b" ");
        encode(&self.target, &mut buf);
        buf.extend_from_slice(b" ");
        encode(&self.protocol, &mut buf);
        buf.extend_from_slice(b"\r\n");
        self.headers.write(&mut buf);
        writer.write_all(&buf)
    }
}

impl Response {
    pub fn read<R: BufRead>(reader: &mut R) -> IoResult<Self> {
        let mut buf = Vec::with_capacity(8192);
        match read_line(reader, &mut buf)? {
            None => Err(IoError::from(IoErrorKind::UnexpectedEof)),
            Some(n) => {
                let mut iter = (&buf[..n]).splitn(3, |c| *c == b' ');
                match (iter.next(), iter.next().and_then(|s| parse(s)), iter.next().unwrap_or_default()) {
                    (Some(protocol), Some(status), phrase) if 100 <= status && status < 600 => Ok(Self {
                        protocol: decode(protocol),
                        status: status as u16,
                        phrase: decode(phrase),
                        headers: Headers::read(reader, &mut buf)?
                    }),
                    _ => Err(IoError::new(IoErrorKind::InvalidData, "invalid status line"))
                }
            }
        }
    }

    pub fn has_body(&self) -> bool {
        200 <= self.status && self.status != 204 && self.status != 304
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        let mut buf = Vec::with_capacity(8192);
        encode(&self.protocol, &mut buf);
        buf.extend_from_slice(b" ");
        encode(&self.status.to_string(), &mut buf);
        buf.extend_from_slice(b" ");
        encode(&self.phrase, &mut buf);
        buf.extend_from_slice(b"\r\n");
        self.headers.write(&mut buf);
        writer.write_all(&buf)
    }
}

impl Display for Host {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(port) = self.port {
            write!(f, "{}:{}", self.name, port)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

impl From<&str> for Host {
    fn from(value: &str) -> Self {
        if let Some((name, port)) = value.rsplit_once(':') {
            if let Ok(port) = u16::from_str_radix(port, 10) {
                return Self { name: name.into(), port: Some(port) }
            }
        }
        Self { name: value.into(), port: None }
    }
}

impl From<&String> for Host {
    fn from(value: &String) -> Self {
        Self::from(value.as_str())
    }
}

impl Host {
    pub fn to_addr(&self) -> Result<IpAddr, AddrParseError> {
        let addr = self.name.as_str();
        if addr.starts_with('[') && addr.ends_with(']') {
            let addr = &addr[1..addr.len()-1];
            addr.parse::<Ipv6Addr>().and_then(|v6| Ok(v6.into()))
        } else {
            addr.parse::<Ipv4Addr>().and_then(|v4| Ok(v4.into()))
        }
    }
}

impl Display for Uri {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}://{}{}", self.scheme, self.host, self.path_and_query)
    }
}

impl FromStr for Uri {
    type Err = UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((scheme, host_path_query)) = s.split_once("://") {
            if let Some(slash) = host_path_query.find('/') {
                let (host, path_and_query) = host_path_query.split_at(slash);
                return Ok(Self { scheme: scheme.into(), host: host.into(), path_and_query: path_and_query.into() })
            }
        }
        Err(UriParseError(UriKind::Absolute))
    }
}

impl Display for UriParseError {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.description())
    }
}

impl Error for UriParseError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        match self.0 {
            UriKind::Absolute => "invalid absolute URI syntax",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_request() {
        let mut cur = Cursor::new(b"\
            GET / HTTP/1.1\r\n\
            Connection: close\r\n\
            \r\n");
        let req = Request::read(&mut cur);
        assert!(req.is_ok());
        let req = req.unwrap();
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "/");
        assert_eq!(req.protocol, "HTTP/1.1");
        assert_eq!(req.headers.get_once("Connection"), Some("close"));
        let mut buf = Vec::new();
        assert!(req.write(&mut buf).is_ok());
        assert_eq!(buf, b"\
            GET / HTTP/1.1\r\n\
            Connection: close\r\n\
            \r\n");

        let mut cur = Cursor::new(b"");
        let req = Request::read(&mut cur);
        assert!(req.is_ok_and(|r| r.is_none()));

        let mut cur = Cursor::new(b"Invalid data\r\n");
        let req = Request::read(&mut cur);
        assert!(req.is_err_and(|e| e.kind() == IoErrorKind::InvalidData));

        let mut cur = Cursor::new(b"Unexpected EOF .\r\n");
        let req = Request::read(&mut cur);
        assert!(req.is_err_and(|e| e.kind() == IoErrorKind::UnexpectedEof));
    }

    #[test]
    fn test_response() {
        let mut cur = Cursor::new(b"\
            HTTP/1.1 200 OK\r\n\
            Connection: close\r\n\
            \r\n");
        let res = Response::read(&mut cur);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.protocol, "HTTP/1.1");
        assert_eq!(res.status, 200);
        assert_eq!(res.phrase, "OK");
        assert_eq!(res.headers.get_once("Connection"), Some("close"));
        let mut buf = Vec::new();
        assert!(res.write(&mut buf).is_ok());
        assert_eq!(buf, b"\
            HTTP/1.1 200 OK\r\n\
            Connection: close\r\n\
            \r\n");

        let mut cur = Cursor::new(b"");
        let res = Response::read(&mut cur);
        assert!(res.is_err_and(|e| e.kind() == IoErrorKind::UnexpectedEof));

        let mut cur = Cursor::new(b"Invalid data\r\n");
        let res = Response::read(&mut cur);
        assert!(res.is_err_and(|e| e.kind() == IoErrorKind::InvalidData));

        let mut cur = Cursor::new(b"Unexpected 500 EOF\r\n");
        let res = Response::read(&mut cur);
        assert!(res.is_err_and(|e| e.kind() == IoErrorKind::UnexpectedEof));
    }

    #[test]
    fn test_uri() {
        let uri = Uri::from_str("http://localhost/");
        assert!(uri.is_ok());
        let uri = uri.unwrap();
        assert_eq!(uri.scheme, "http");
        assert_eq!(uri.host.name, "localhost");
        assert_eq!(uri.host.port, None);
        assert_eq!(uri.path_and_query, "/");
        assert_eq!(uri.to_string(), "http://localhost/");

        let uri = Uri::from_str("https://[::1]:443/path?query");
        assert!(uri.is_ok());
        let uri = uri.unwrap();
        assert_eq!(uri.scheme, "https");
        assert_eq!(uri.host.name, "[::1]");
        assert_eq!(uri.host.port, Some(443));
        assert_eq!(uri.path_and_query, "/path?query");
        assert_eq!(uri.to_string(), "https://[::1]:443/path?query");

        let uri = Uri::from_str("invalid URI");
        assert!(uri.is_err());
    }
}
