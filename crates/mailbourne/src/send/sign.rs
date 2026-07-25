//! # 1 · sign — seal it
//!
//! Before a message leaves, we stamp it with a **DKIM signature**: a hash of
//! selected headers and the body, encrypted with our private key. Receivers
//! fetch the matching public key from DNS (`<selector>._domainkey.<domain>`)
//! and verify the seal — proving the message really came from our domain
//! and wasn't altered in transit.
//!
//! The signature is canonicalization-exact: it covers *these bytes*. That is
//! why [`crate::shared::core::Message`] is stored raw and never re-serialized.
//!
//! The cryptography rides [`mail_auth`] (fuzzed, battle-tested) — we never
//! hand-roll the crypto; this module only owns the ergonomics. Key
//! *management* (minting a keypair, deriving its record) lives in
//! [`crate::shared::dkim`], which needs no network stack and is always available.

use crate::shared::core::Message;
use crate::shared::dkim::DkimError;

/// Seals `message` with an RSA-SHA256 DKIM signature and returns the
/// message with its `DKIM-Signature` header prepended.
///
/// - `domain` + `selector` tell verifiers where in DNS the public key
///   lives: `<selector>._domainkey.<domain>`.
/// - `rsa_private_key_pem` is the RSA private key as PEM, in either
///   container: PKCS#1 (`BEGIN RSA PRIVATE KEY`, LibreSSL's default) or
///   PKCS#8 (`BEGIN PRIVATE KEY`, OpenSSL 3's default). It never leaves
///   the machine; only its public half is published.
///
/// The original bytes are preserved untouched after the new header —
/// signing *adds*, never rewrites.
///
/// # Errors
/// [`DkimError::BadKey`] for an unreadable key, [`DkimError::Signing`]
/// when the signer refuses. Both mean: fix configuration, don't send.
pub fn dkim_sign(
    message: &Message,
    domain: &str,
    selector: &str,
    rsa_private_key_pem: &str,
) -> Result<Message, DkimError> {
    use mail_auth::common::crypto::{RsaKey, Sha256};
    use mail_auth::common::headers::HeaderWriter;
    use mail_auth::dkim::DkimSigner;
    use rustls_pki_types::PrivateKeyDer;
    use rustls_pki_types::pem::PemObject;

    // Accept any PEM container — PKCS#1 ("BEGIN RSA PRIVATE KEY", what
    // LibreSSL writes) and PKCS#8 ("BEGIN PRIVATE KEY", what OpenSSL 3
    // writes). Same key inside; users should never have to know the
    // difference.
    let key_der = PrivateKeyDer::from_pem_slice(rsa_private_key_pem.as_bytes())
        .map_err(|e| DkimError::BadKey(e.to_string()))?;
    let key =
        RsaKey::<Sha256>::from_key_der(key_der).map_err(|e| DkimError::BadKey(e.to_string()))?;

    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(message.raw())
        .map_err(|e| DkimError::Signing(e.to_string()))?;

    let mut sealed = signature.to_header().into_bytes();
    sealed.extend_from_slice(message.raw());
    Ok(Message::from_raw(sealed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::dkim::{TEST_KEY, TEST_KEY_PKCS8, generate_dkim_keypair};

    const LETTER: &[u8] = b"From: alice@us.example\r\n\
To: bob@fake.mx\r\n\
Subject: sealed\r\n\
\r\n\
wax and string\r\n";

    fn signed() -> Message {
        dkim_sign(
            &Message::from_raw(LETTER.to_vec()),
            "us.example",
            "mb2026",
            TEST_KEY,
        )
        .unwrap()
    }

    #[test]
    fn sealing_prepends_a_dkim_signature_header() {
        let sealed = signed();
        let text = String::from_utf8_lossy(sealed.raw());
        assert!(text.starts_with("DKIM-Signature:"), "got: {text}");
    }

    #[test]
    fn the_seal_names_our_domain_and_selector() {
        let sealed = signed();
        let text = String::from_utf8_lossy(sealed.raw());
        let header = text.split("\r\nFrom:").next().unwrap();
        assert!(header.contains("d=us.example"), "got: {header}");
        assert!(header.contains("s=mb2026"), "got: {header}");
        assert!(header.contains("b="), "no signature bytes: {header}");
        assert!(header.contains("bh="), "no body hash: {header}");
    }

    #[test]
    fn the_original_letter_is_preserved_byte_for_byte() {
        let sealed = signed();
        assert!(
            sealed.raw().ends_with(LETTER),
            "signing must add, never rewrite"
        );
    }

    #[test]
    fn a_pkcs8_key_signs_identically_to_its_pkcs1_twin() {
        // OpenSSL 3 writes PKCS#8 ("BEGIN PRIVATE KEY"); LibreSSL writes
        // PKCS#1 ("BEGIN RSA PRIVATE KEY"). Same key inside — both must
        // produce a valid signature.
        let sealed = dkim_sign(
            &Message::from_raw(LETTER.to_vec()),
            "us.example",
            "mb2026",
            TEST_KEY_PKCS8,
        )
        .unwrap();
        let text = String::from_utf8_lossy(sealed.raw());
        assert!(text.starts_with("DKIM-Signature:"), "got: {text}");
        assert!(text.contains("s=mb2026"));
    }

    #[test]
    fn an_unreadable_key_refuses_to_sign() {
        let err = dkim_sign(
            &Message::from_raw(LETTER.to_vec()),
            "us.example",
            "mb2026",
            "not a key at all",
        )
        .unwrap_err();
        assert!(matches!(err, DkimError::BadKey(_)));
    }

    #[test]
    fn a_minted_key_signs_a_message_successfully() {
        // The strongest possible proof a minted PEM is well-formed: the
        // signing path accepts it end to end.
        let pair = generate_dkim_keypair().unwrap();
        let sealed = dkim_sign(
            &Message::from_raw(b"From: a@b.c\r\n\r\nhi\r\n".to_vec()),
            "b.c",
            "fresh",
            &pair.private_key_pem,
        )
        .unwrap();
        assert!(sealed.raw().starts_with(b"DKIM-Signature:"));
    }
}
