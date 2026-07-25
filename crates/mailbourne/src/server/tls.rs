//! # tls — the server's certificate for STARTTLS
//!
//! Builds the [`TlsAcceptor`] the receiving session uses to upgrade a
//! connection to encryption. Two ways to get one: load a real certificate
//! (from Let's Encrypt or another CA — required for clients like Gmail that
//! verify it), or mint a throwaway **self-signed** one on the spot so
//! STARTTLS works out of the box for local testing and opportunistic
//! server-to-server encryption.
//!
//! The crypto is `ring` (the same backend the outbound side pins), so this
//! cross-compiles cleanly to the static-musl single binary.

use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Builds an acceptor from a PEM certificate chain and private key.
///
/// # Errors
/// [`std::io::Error`] if the PEM can't be read or the cert/key don't form a
/// valid server configuration.
pub fn acceptor_from_pem(cert_pem: &str, key_pem: &str) -> std::io::Result<TlsAcceptor> {
    use tokio_rustls::rustls::pki_types::pem::PemObject;

    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    build(certs, key)
}

/// Mints a throwaway self-signed certificate for `hostname` and builds an
/// acceptor from it. Fine for local testing and opportunistic TLS between
/// mail servers; a real certificate is needed for clients that verify it.
///
/// # Errors
/// [`std::io::Error`] if key generation or the server config fails.
pub fn self_signed(hostname: &str) -> std::io::Result<TlsAcceptor> {
    let cert = rcgen::generate_simple_self_signed(vec![hostname.to_string()])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    build(vec![cert_der], key)
}

/// Assembles a `ring`-backed acceptor from a validated cert + key.
fn build(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> std::io::Result<TlsAcceptor> {
    // Explicit provider: never let ambient crate features pick the crypto.
    let config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| std::io::Error::other(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_self_signed_acceptor_builds() {
        // If this constructs, the ring provider + cert wiring are sound; the
        // full STARTTLS handshake is proven in the session tests.
        assert!(self_signed("mail.test").is_ok());
    }

    #[test]
    fn garbage_pem_is_refused() {
        assert!(acceptor_from_pem("not a cert", "not a key").is_err());
    }
}
