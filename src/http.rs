use std::borrow::Cow;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{BufRead, Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct Headers {
    entries: Vec<(Cow<'static, str>, Cow<'static, str>)>,
}

#[derive(Clone)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub protocol: String,
    pub headers: Headers,
}

#[derive(Clone)]
pub struct Response {
    pub protocol: String,
    pub status: u16,
    pub phrase: String,
    pub headers: Headers,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub port: Option<u16>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Uri {
    pub scheme: String,
    pub host: Host,
    pub path_and_query: String,
}

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

    pub fn push<S: Into<Cow<'static, str>>>(&mut self, name: S, value: S) {
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

impl Host {
    pub fn parse(host: &str) -> Self {
        if let Some((name, port)) = host.rsplit_once(':') {
            if let Ok(port) = u16::from_str_radix(port, 10) {
                return Self { name: name.into(), port: Some(port) }
            }
        }
        Self { name: host.into(), port: None }
    }

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

impl Uri {
    pub fn parse(uri: &str) -> Option<Self> {
        uri.split_once("://").and_then(|(scheme, host_path_query)| {
            host_path_query.find('/').and_then(|slash| {
                let (host, path_and_query) = host_path_query.split_at(slash);
                Some(Self { scheme: scheme.into(), host: Host::parse(host), path_and_query: path_and_query.into() })
            })
        })
    }
}
