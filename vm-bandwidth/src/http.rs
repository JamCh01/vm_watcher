//! Minimal blocking HTTP client over `std::net::TcpStream` (no TLS).
//!
//! Deliberately tiny: the daemon POSTs one metrics payload per push interval to
//! localhost VictoriaMetrics, and the `--ui` trend screen GETs one query per
//! refresh. A full HTTP stack (reqwest/hyper/tokio) would be far more machinery
//! than these two call sites need.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context, Result};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Parsed `http://host[:port][/path]` URL (https is rejected by config validation).
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(url: &str) -> Result<Url> {
    let rest = url
        .strip_prefix("http://")
        .with_context(|| format!("only http:// URLs are supported: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .with_context(|| format!("bad port in {url}"))?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        bail!("URL has no host: {url}");
    }
    Ok(Url { host, port, path })
}

fn connect(url: &Url) -> Result<TcpStream> {
    let mut last = None;
    for addr in (url.host.as_str(), url.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", url.host))?
    {
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(s) => {
                s.set_read_timeout(Some(TIMEOUT))?;
                s.set_write_timeout(Some(TIMEOUT))?;
                return Ok(s);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .unwrap_or_else(|| std::io::Error::other("no addresses"))
        .into())
}

/// Percent-encode a value for use in a query string (RFC 3986 unreserved set kept).
pub fn percent_encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Read one response: status code + body (Content-Length or chunked).
fn read_response(stream: &mut TcpStream) -> Result<(u16, String)> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    // Read until the end of headers.
    let header_end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            bail!("connection closed before headers were complete");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 1 << 20 {
            bail!("headers larger than 1 MiB");
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut status = 0u16;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for (i, line) in headers.lines().enumerate() {
        if i == 0 {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            continue;
        }
        let (name, value) = line.split_once(':').unwrap_or(("", ""));
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let body_start = header_end + 4;
    let mut body: Vec<u8> = buf[body_start..].to_vec();

    if let Some(want) = content_length {
        while body.len() < want {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                bail!("connection closed before the body was complete");
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(want);
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    } else if chunked {
        // Decode chunked framing. Bodies here are small JSON documents.
        let mut decoded: Vec<u8> = Vec::new();
        let mut rest: Vec<u8> = body;
        loop {
            // Need one CRLF-terminated size line.
            let size = loop {
                if let Some(pos) = find_crlf(&rest) {
                    let line = String::from_utf8_lossy(&rest[..pos]);
                    let size = usize::from_str_radix(line.trim(), 16)
                        .with_context(|| format!("bad chunk size {line:?}"))?;
                    rest.drain(..pos + 2);
                    break size;
                }
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    bail!("connection closed mid-chunk");
                }
                rest.extend_from_slice(&chunk[..n]);
            };
            if size == 0 {
                break;
            }
            while rest.len() < size + 2 {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    bail!("connection closed mid-chunk");
                }
                rest.extend_from_slice(&chunk[..n]);
            }
            decoded.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
        Ok((status, String::from_utf8_lossy(&decoded).into_owned()))
    } else {
        // No length information: read to EOF (Connection: close requests get this).
        loop {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// POST `body` to `url`; returns the status code. Errors on non-2xx.
pub fn post(url: &str, content_type: &str, body: &str) -> Result<()> {
    let url = parse_url(url)?;
    let mut stream = connect(&url)?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        url.path,
        url.host,
        body.len(),
        body
    );
    stream.write_all(req.as_bytes())?;
    let (status, resp_body) = read_response(&mut stream)?;
    if !(200..300).contains(&status) {
        bail!(
            "HTTP {status}: {}",
            resp_body.chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

/// GET `url`; returns the body. Errors on non-2xx.
pub fn get(url: &str) -> Result<String> {
    let url = parse_url(url)?;
    let mut stream = connect(&url)?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        url.path, url.host
    );
    stream.write_all(req.as_bytes())?;
    let (status, body) = read_response(&mut stream)?;
    if !(200..300).contains(&status) {
        bail!(
            "HTTP {status}: {}",
            body.chars().take(200).collect::<String>()
        );
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        let u = parse_url("http://127.0.0.1:8428").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("127.0.0.1", 8428, "/")
        );
        let u = parse_url("http://vm.internal:9090/prefix").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("vm.internal", 9090, "/prefix")
        );
        assert!(parse_url("https://x").is_err());
        assert!(parse_url("http://").is_err());
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(
            percent_encode("rate(vmbw_rx_bytes_total{ip=\"1.2.3.4\"}[2m]) * 8"),
            "rate%28vmbw_rx_bytes_total%7Bip%3D%221.2.3.4%22%7D%5B2m%5D%29%20%2A%208"
        );
    }
}
