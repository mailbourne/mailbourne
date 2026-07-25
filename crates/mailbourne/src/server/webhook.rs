//! # webhook — deliver by HTTP POST
//!
//! A [`DeliveryTarget`] that announces an accepted message to a URL: it POSTs
//! a small JSON summary (envelope + size + `Message-ID`) and treats any `2xx`
//! as success. A non-`2xx` or a transport error is a **retryable** failure —
//! the spool holds the message and the worker tries again with backoff, so a
//! briefly-down endpoint never loses mail (webhooks are at-least-once).
//!
//! The HTTP client is hand-rolled over `tokio` + the same TLS dial the SMTP
//! sender uses ([`crate::send::dial`]) — no heavyweight HTTP dependency, in
//! keeping with the single-static-binary promise. It's deliberately minimal:
//! one request, read the status line, done.

use crate::server::inbound::session::ReceivedMessage;
use crate::server::route::{DeliveryOutcome, DeliveryTarget};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls::RootCertStore;

/// How long any single webhook attempt may take before it's a failure.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Delivers accepted mail to an HTTP endpoint as a JSON event.
pub struct WebhookTarget {
    url: String,
    roots: RootCertStore,
    timeout: Duration,
}

impl WebhookTarget {
    /// A webhook target posting to `url` (http or https), verifying TLS
    /// against the standard public root set.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            roots: crate::send::dial::webpki_trust_roots(),
            timeout: TIMEOUT,
        }
    }
}

/// The JSON body posted for an accepted inbound message.
#[derive(serde::Serialize)]
struct Payload<'a> {
    /// Always `"received"` for now — room for delivery/bounce events later.
    event: &'a str,
    /// Envelope sender (`""` for the null sender).
    mail_from: &'a str,
    /// Envelope recipients.
    rcpt_to: &'a [String],
    /// Raw message size in bytes.
    size: usize,
    /// The `Message-ID` header, if the message carried one.
    message_id: Option<String>,
}

#[async_trait]
impl DeliveryTarget for WebhookTarget {
    fn name(&self) -> &str {
        "webhook"
    }

    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        let payload = Payload {
            event: "received",
            mail_from: &message.mail_from,
            rcpt_to: &message.rcpt_to,
            size: message.data.len(),
            message_id: message_id(&message.data),
        };
        let body = match serde_json::to_vec(&payload) {
            Ok(body) => body,
            Err(e) => return DeliveryOutcome::Failed(format!("could not encode webhook: {e}")),
        };

        match self.post(&body).await {
            Ok(code) if (200..300).contains(&code) => DeliveryOutcome::Delivered,
            Ok(code) => DeliveryOutcome::Failed(format!("webhook endpoint returned {code}")),
            Err(e) => DeliveryOutcome::Failed(format!("webhook POST failed: {e}")),
        }
    }
}

impl WebhookTarget {
    /// POSTs `body` to the configured URL and returns the HTTP status code.
    async fn post(&self, body: &[u8]) -> std::io::Result<u16> {
        let url = parse_url(&self.url)?;
        let tcp = tokio::time::timeout(
            self.timeout,
            TcpStream::connect((url.host.as_str(), url.port)),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;

        let exchange = async {
            if url.https {
                let tls = crate::send::dial::secure(tcp, &url.host, self.roots.clone()).await?;
                write_and_read_status(tls, &url.host, &url.path, body).await
            } else {
                write_and_read_status(tcp, &url.host, &url.path, body).await
            }
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "webhook timed out"))?
    }
}

/// A minimally-parsed URL: enough for an HTTP client, no more.
#[derive(Debug, PartialEq, Eq)]
struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

/// Parses `http(s)://host[:port][/path]`. Anything else is an error.
fn parse_url(url: &str) -> std::io::Result<Url> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, m.to_string());
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| bad("url has no scheme"))?;
    let https = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(bad(&format!("unsupported scheme: {other}"))),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| bad("invalid port"))?),
        None => (authority.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(bad("url has no host"));
    }
    Ok(Url {
        https,
        host,
        port,
        path,
    })
}

/// Writes one `POST` and returns the response's status code. Reads only the
/// status line — a webhook cares whether it was accepted, not the body.
async fn write_and_read_status<S>(
    stream: S,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<u16>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: mailbourne\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    write.write_all(head.as_bytes()).await?;
    write.write_all(body).await?;
    write.flush().await?;

    let mut reader = BufReader::new(read);
    let mut status = String::new();
    reader.read_line(&mut status).await?;
    // "HTTP/1.1 200 OK" → the middle token is the code.
    status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("not an HTTP status line: {status:?}"),
            )
        })
}

/// Best-effort extraction of the `Message-ID` header value.
fn message_id(data: &[u8]) -> Option<String> {
    // Headers end at the first blank line; scan only that region.
    let headers = data.split(|&b| b == b'\n').take_while(|line| {
        let trimmed: &[u8] = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        !trimmed.is_empty()
    });
    for line in headers {
        let line = String::from_utf8_lossy(line);
        if let Some(value) = line
            .strip_prefix("Message-ID:")
            .or_else(|| line.strip_prefix("Message-Id:"))
            .or_else(|| line.strip_prefix("message-id:"))
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn message(data: &[u8]) -> ReceivedMessage {
        ReceivedMessage {
            mail_from: "alice@sender.test".to_string(),
            rcpt_to: vec!["bob@us.example".to_string()],
            data: data.to_vec(),
        }
    }

    /// Reads a full HTTP request off `stream` and returns the body bytes.
    async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut reader = BufReader::new(stream);
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await.unwrap();
        String::from_utf8_lossy(&body).into_owned()
    }

    /// A one-shot plain-HTTP server that replies with `status` and returns
    /// the request body it received.
    async fn http_once(status: &'static str) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let body = read_request(&mut stream).await;
            stream
                .write_all(
                    format!("{status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
            body
        });
        (format!("http://127.0.0.1:{port}/hook"), handle)
    }

    #[tokio::test]
    async fn posts_the_envelope_and_reports_delivered_on_2xx() {
        let (url, handle) = http_once("HTTP/1.1 200 OK").await;
        let target = WebhookTarget::new(url);

        let outcome = target
            .deliver(&message(b"Message-ID: <abc@x>\r\nSubject: hi\r\n\r\nbody"))
            .await;
        assert!(matches!(outcome, DeliveryOutcome::Delivered));

        let body = handle.await.unwrap();
        assert!(body.contains("alice@sender.test"), "body: {body}");
        assert!(body.contains("bob@us.example"), "body: {body}");
        assert!(body.contains("<abc@x>"), "message-id missing: {body}");
        assert!(body.contains("\"event\":\"received\""), "body: {body}");
    }

    #[tokio::test]
    async fn a_5xx_response_is_a_retryable_failure() {
        let (url, handle) = http_once("HTTP/1.1 503 Service Unavailable").await;
        let target = WebhookTarget::new(url);

        let outcome = target.deliver(&message(b"\r\nno headers")).await;
        assert!(matches!(outcome, DeliveryOutcome::Failed(_)));
        let _ = handle.await;
    }

    #[tokio::test]
    async fn a_dead_endpoint_is_a_retryable_failure() {
        // Nothing is listening — the connect fails, which must be retryable.
        let target = WebhookTarget::new("http://127.0.0.1:1/hook");
        let outcome = target.deliver(&message(b"\r\nx")).await;
        assert!(matches!(outcome, DeliveryOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn it_posts_over_real_tls() {
        use tokio_rustls::TlsAcceptor;
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

        // A self-signed https server for "localhost"; we trust exactly it.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivatePkcs8KeyDer::from(key_der).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let body = read_request(&mut tls).await;
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            body
        });

        let mut roots = RootCertStore::empty();
        roots
            .add(tokio_rustls::rustls::pki_types::CertificateDer::from(
                cert_der,
            ))
            .unwrap();
        let target = WebhookTarget {
            url: format!("https://localhost:{port}/hook"),
            roots,
            timeout: TIMEOUT,
        };

        let outcome = target.deliver(&message(b"\r\nsecure body")).await;
        assert!(matches!(outcome, DeliveryOutcome::Delivered), "{outcome:?}");
        let body = server.await.unwrap();
        assert!(body.contains("alice@sender.test"), "body: {body}");
    }

    #[test]
    fn parse_url_fills_in_ports_and_paths() {
        assert_eq!(
            parse_url("http://example.com/hook").unwrap(),
            Url {
                https: false,
                host: "example.com".into(),
                port: 80,
                path: "/hook".into()
            }
        );
        assert_eq!(
            parse_url("https://example.com").unwrap(),
            Url {
                https: true,
                host: "example.com".into(),
                port: 443,
                path: "/".into()
            }
        );
        assert_eq!(
            parse_url("http://h.test:8080/a/b?c=d").unwrap(),
            Url {
                https: false,
                host: "h.test".into(),
                port: 8080,
                path: "/a/b?c=d".into()
            }
        );
        assert!(parse_url("ftp://nope").is_err());
        assert!(parse_url("no-scheme.test/x").is_err());
    }

    #[test]
    fn message_id_is_extracted_or_none() {
        assert_eq!(
            message_id(b"From: a@b\r\nMessage-ID: <id@host>\r\n\r\nbody"),
            Some("<id@host>".to_string())
        );
        // Case-insensitive header name.
        assert_eq!(
            message_id(b"message-id: <lower@host>\r\n\r\nbody"),
            Some("<lower@host>".to_string())
        );
        // A Message-ID only in the body must not be picked up.
        assert_eq!(message_id(b"Subject: hi\r\n\r\nMessage-ID: <fake>"), None);
        assert_eq!(message_id(b"\r\nno headers"), None);
    }
}
