//! # acme::http — a small HTTPS client for the ACME protocol
//!
//! ACME is a REST-ish conversation with the CA, and it needs more than the
//! webhook's fire-and-forget POST: it reads response **headers** (the
//! `Replay-Nonce` every request consumes, the `Location` a new account or
//! order is returned in) and **bodies** (JSON, and the certificate PEM). So
//! this is a slightly fuller hand-rolled client — GET and POST, status +
//! headers + body — still over the same `ring`-backed TLS the sender uses,
//! verifying the CA against the public roots. No HTTP dependency.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// One HTTP response: status, headers, and the full body.
#[derive(Debug)]
pub struct Response {
    /// The numeric status code (e.g. `200`, `201`).
    pub status: u16,
    /// Response headers, in order.
    headers: Vec<(String, String)>,
    /// The full response body.
    pub body: Vec<u8>,
}

impl Response {
    /// The first header matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as UTF-8 (lossy) — for JSON responses.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// GETs `url` over HTTPS.
///
/// # Errors
/// [`std::io::Error`] if the connection, TLS handshake, or read fails.
pub async fn get(url: &str) -> std::io::Result<Response> {
    request("GET", url, None, &[]).await
}

/// POSTs `body` to `url` with `content_type` over HTTPS.
///
/// # Errors
/// [`std::io::Error`] if the connection, TLS handshake, or read fails.
pub async fn post(url: &str, content_type: &str, body: &[u8]) -> std::io::Result<Response> {
    request("POST", url, Some(content_type), body).await
}

/// Performs one HTTPS request and reads the whole response.
async fn request(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> std::io::Result<Response> {
    let (host, port, path) = parse_https(url)?;

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let tls =
        crate::send::dial::secure(tcp, &host, crate::send::dial::webpki_trust_roots()).await?;
    let (read, mut write) = tokio::io::split(tls);

    let mut head = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: mailbourne\r\n\
         Accept: */*\r\n\
         Connection: close\r\n"
    );
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    write.write_all(head.as_bytes()).await?;
    write.write_all(body).await?;
    write.flush().await?;

    read_response(BufReader::new(read)).await
}

/// Reads a full HTTP/1.1 response: status line, headers, then the body —
/// handling `Content-Length`, `Transfer-Encoding: chunked`, and
/// close-delimited bodies.
async fn read_response<R: AsyncBufRead + Unpin>(mut reader: R) -> std::io::Result<Response> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());

    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| bad(&format!("not an HTTP status line: {status_line:?}")))?;

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().ok();
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.eq_ignore_ascii_case("chunked")
            {
                chunked = true;
            }
            headers.push((name, value));
        }
    }

    let body = if chunked {
        read_chunked(&mut reader).await?
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        buf
    } else {
        // No length given → the body runs to end-of-stream (Connection: close).
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        buf
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Decodes a `Transfer-Encoding: chunked` body.
async fn read_chunked<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;
        // A chunk size may carry `;ext` — take the hex before it.
        let hex = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).unwrap_or(0);
        if size == 0 {
            // Consume the terminating CRLF (and any trailer line).
            let mut end = String::new();
            let _ = reader.read_line(&mut end).await?;
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);
        let mut crlf = String::new();
        reader.read_line(&mut crlf).await?; // the CRLF after the chunk data
    }
    Ok(body)
}

/// Parses `https://host[:port]/path` into `(host, port, path)`. ACME URLs are
/// always HTTPS.
fn parse_https(url: &str) -> std::io::Result<(String, u16, String)> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, m.to_string());
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| bad("ACME URLs must be https"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| bad("invalid port"))?),
        None => (authority.to_string(), 443),
    };
    if host.is_empty() {
        return Err(bad("url has no host"));
    }
    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(raw: &[u8]) -> Response {
        read_response(BufReader::new(raw)).await.unwrap()
    }

    #[tokio::test]
    async fn a_content_length_response_is_read_with_its_headers() {
        let raw = b"HTTP/1.1 201 Created\r\n\
                    Replay-Nonce: abc123\r\n\
                    Location: https://acme.test/acct/1\r\n\
                    Content-Length: 11\r\n\r\n\
                    hello world";
        let resp = parse(raw).await;
        assert_eq!(resp.status, 201);
        assert_eq!(resp.header("replay-nonce"), Some("abc123")); // case-insensitive
        assert_eq!(resp.header("Location"), Some("https://acme.test/acct/1"));
        assert_eq!(resp.body, b"hello world");
    }

    #[tokio::test]
    async fn a_chunked_response_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let resp = parse(raw).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
    }

    #[tokio::test]
    async fn a_close_delimited_body_runs_to_end() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nthe rest is the body";
        let resp = parse(raw).await;
        assert_eq!(resp.body, b"the rest is the body");
    }

    #[test]
    fn parse_https_fills_in_the_port_and_path() {
        assert_eq!(
            parse_https("https://acme.test/dir").unwrap(),
            ("acme.test".to_string(), 443, "/dir".to_string())
        );
        assert_eq!(
            parse_https("https://h:8443/a/b").unwrap(),
            ("h".to_string(), 8443, "/a/b".to_string())
        );
        assert!(parse_https("http://insecure.test").is_err());
    }
}
