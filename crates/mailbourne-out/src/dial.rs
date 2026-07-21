//! # 3 · dial — knock on the door
//!
//! Two small, honest jobs:
//!
//! - [`connect`]: open a TCP connection to an MX host, with a timeout —
//!   because a filtered port 25 doesn't refuse, it *goes silent*, and
//!   waiting forever on silence is how queues stall.
//! - [`secure`]: transform an open stream into a TLS stream (the mechanics
//!   behind `STARTTLS` — the *choreography* lives in
//!   [`conversation::deliver_with_starttls`](crate::conversation::deliver_with_starttls)).
//!
//! If the dial fails, that is a *temporary* condition: try the next MX
//! host, and if all are silent, the message returns to the queue.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Why the knock went unanswered.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// Nobody answered within the timeout. On port 25 this is very often a
    /// provider block ("filtered"), not a dead server — the doctor's S1
    /// check exists exactly for this signature.
    #[error("timed out dialing {addr} after {waited:?}")]
    Timeout {
        /// The address we tried.
        addr: SocketAddr,
        /// How long we waited before giving up.
        waited: Duration,
    },
    /// The host answered — with a slammed door (connection refused) or
    /// another socket error.
    #[error("could not connect to {addr}: {source}")]
    Refused {
        /// The address we tried.
        addr: SocketAddr,
        /// The underlying socket error.
        source: std::io::Error,
    },
}

/// Opens a TCP connection to `addr`, waiting at most `timeout`.
///
/// # Errors
/// [`DialError::Timeout`] when the address stays silent (the classic
/// blocked-port-25 signature), [`DialError::Refused`] when the connection
/// fails outright. Both are temporary from the queue's point of view: try
/// the next MX host, then retry later.
pub async fn connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, DialError> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(source)) => Err(DialError::Refused { addr, source }),
        Err(_elapsed) => Err(DialError::Timeout {
            addr,
            waited: timeout,
        }),
    }
}

/// Upgrades an open stream to TLS, verifying the server against `roots`.
///
/// This is the transformation moment of `STARTTLS`: same TCP connection,
/// but from here on the dialogue is private. Production callers use
/// [`webpki_trust_roots`] (the standard browser root set); tests hand in
/// their own root so no real certificate authority is needed.
///
/// # Errors
/// An [`std::io::Error`] when the handshake fails — including the case that
/// matters most: the server's certificate doesn't match `server_name`.
pub async fn secure(
    stream: TcpStream,
    server_name: &str,
    roots: RootCertStore,
) -> std::io::Result<TlsStream<TcpStream>> {
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    connector.connect(name, stream).await
}

/// The standard public trust roots (Mozilla's, via `webpki-roots`) —
/// what [`secure`] should be given when dialing real mail servers.
pub fn webpki_trust_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connects_to_a_listening_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stream = connect(addr, Duration::from_secs(1)).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn a_closed_port_is_refused_not_timed_out() {
        // Bind a port, learn its number, drop it — now nothing listens there.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = connect(addr, Duration::from_secs(1)).await.unwrap_err();
        assert!(matches!(err, DialError::Refused { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn silence_becomes_a_timeout() {
        // 10.255.255.1 is a private-range blackhole: packets go out,
        // nothing comes back — the signature of a filtered port.
        let addr: SocketAddr = "10.255.255.1:25".parse().unwrap();

        let err = connect(addr, Duration::from_millis(300)).await.unwrap_err();
        assert!(matches!(err, DialError::Timeout { .. }), "got {err:?}");
    }

    // ── TLS: a real handshake against a self-signed local server ────────

    /// A local TLS server with a fresh self-signed cert for `fake.mx`.
    /// Returns (address, the cert to trust).
    async fn tls_server() -> (SocketAddr, Vec<u8>) {
        use tokio_rustls::TlsAcceptor;
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

        let cert = rcgen::generate_simple_self_signed(vec!["fake.mx".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivatePkcs8KeyDer::from(key_der).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let mut buf = [0u8; 5];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.write_all(b"hello").await;
                    }
                });
            }
        });

        (addr, cert_der)
    }

    fn trust_only(cert_der: &[u8]) -> RootCertStore {
        use tokio_rustls::rustls::pki_types::CertificateDer;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der.to_vec())).unwrap();
        roots
    }

    #[tokio::test]
    async fn a_trusted_certificate_completes_the_handshake() {
        let (addr, cert) = tls_server().await;
        let tcp = connect(addr, Duration::from_secs(1)).await.unwrap();

        let mut tls = secure(tcp, "fake.mx", trust_only(&cert)).await.unwrap();
        tls.write_all(b"ping!").await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn a_name_mismatch_fails_the_handshake() {
        // The cert says "fake.mx"; we dial claiming to expect "other.mx".
        // This failing is the entire point of TLS verification.
        let (addr, cert) = tls_server().await;
        let tcp = connect(addr, Duration::from_secs(1)).await.unwrap();

        let result = secure(tcp, "other.mx", trust_only(&cert)).await;
        assert!(result.is_err());
    }

    #[test]
    fn the_public_root_set_is_not_empty() {
        assert!(!webpki_trust_roots().is_empty());
    }
}
