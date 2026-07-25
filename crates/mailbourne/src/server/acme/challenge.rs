//! # acme::challenge — the HTTP-01 responder
//!
//! The small web server that proves domain control: while a certificate is
//! being obtained, Let's Encrypt fetches
//! `http://<domain>/.well-known/acme-challenge/<token>` and expects the
//! key-authorization back. This binds **port 80**, holds the presented tokens,
//! and answers exactly that path — nothing else. It implements
//! [`Http01Solver`](super::order::Http01Solver), so the order flow just calls
//! `present` and the CA can validate.
//!
//! HTTP-01 needs no credentials at all (contrast DNS-01's API token) — it's
//! the safe default, which is why it's the challenge mailbourne ships first.

use super::order::Http01Solver;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A port-80 web server answering ACME HTTP-01 challenges.
pub struct Http01Responder {
    tokens: Arc<Mutex<HashMap<String, String>>>,
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Http01Responder {
    /// Binds `addr` (e.g. `0.0.0.0:80`) and starts answering challenges.
    ///
    /// # Errors
    /// [`std::io::Error`] if the address can't be bound (port 80 needs
    /// privilege, or is already in use).
    pub async fn start(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let tokens: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        let served = tokens.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let served = served.clone();
                tokio::spawn(async move {
                    let _ = answer(stream, served).await;
                });
            }
        });
        Ok(Self { tokens, addr, task })
    }

    /// The address actually bound (useful when `:0` picked an ephemeral port).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Http01Responder {
    fn drop(&mut self) {
        // Stop listening the moment issuance is done.
        self.task.abort();
    }
}

#[async_trait]
impl Http01Solver for Http01Responder {
    async fn present(&self, token: &str, key_authorization: &str) {
        self.tokens
            .lock()
            .unwrap()
            .insert(token.to_string(), key_authorization.to_string());
    }

    async fn cleanup(&self, token: &str) {
        self.tokens.lock().unwrap().remove(token);
    }
}

/// Answers one HTTP request: the key-authorization for a known challenge
/// token, or `404` for anything else.
async fn answer(
    mut stream: TcpStream,
    tokens: Arc<Mutex<HashMap<String, String>>>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.split();
    let mut request_line = String::new();
    BufReader::new(read).read_line(&mut request_line).await?;

    // "GET /.well-known/acme-challenge/<token> HTTP/1.1"
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let response = match path.strip_prefix("/.well-known/acme-challenge/") {
        Some(token) => match tokens.lock().unwrap().get(token).cloned() {
            Some(key_authorization) => format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{key_authorization}",
                key_authorization.len()
            ),
            None => not_found(),
        },
        None => not_found(),
    };
    write.write_all(response.as_bytes()).await?;
    write.flush().await
}

fn not_found() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Minimal plaintext HTTP GET, returning the whole raw response.
    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn it_serves_a_presented_token_and_404s_everything_else() {
        let responder = Http01Responder::start("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = responder.local_addr();
        responder.present("tok1", "tok1.thumbprint").await;

        let hit = http_get(addr, "/.well-known/acme-challenge/tok1").await;
        assert!(hit.starts_with("HTTP/1.1 200"), "got: {hit}");
        assert!(hit.ends_with("tok1.thumbprint"), "body missing: {hit}");

        let miss = http_get(addr, "/.well-known/acme-challenge/unknown").await;
        assert!(miss.starts_with("HTTP/1.1 404"), "got: {miss}");

        let other = http_get(addr, "/something-else").await;
        assert!(other.starts_with("HTTP/1.1 404"), "got: {other}");

        // After cleanup, the token is gone.
        responder.cleanup("tok1").await;
        let gone = http_get(addr, "/.well-known/acme-challenge/tok1").await;
        assert!(gone.starts_with("HTTP/1.1 404"), "got: {gone}");
    }
}
