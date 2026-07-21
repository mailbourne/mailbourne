//! # 1 · sign — seal it
//!
//! Before a message leaves, we stamp it with a **DKIM signature**: a hash of
//! selected headers and the body, encrypted with our private key. Receivers
//! fetch the matching public key from DNS (`<selector>._domainkey.<domain>`)
//! and verify the seal — proving the message really came from our domain
//! and wasn't altered in transit.
//!
//! The signature is canonicalization-exact: it covers *these bytes*. That is
//! why [`mailbourne_core::Message`] is stored raw and never re-serialized.
//!
//! The cryptography rides [`mail_auth`] (fuzzed, battle-tested) — we never
//! hand-roll the crypto; this module only owns the ergonomics.

use mailbourne_core::Message;

/// Why sealing failed. All of these are configuration problems, not mail
/// problems — a signing failure should stop the send, loudly, before
/// anything reaches the wire unsigned.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The private key could not be read (not a PEM-encoded RSA key in
    /// either PKCS#1 or PKCS#8 form).
    #[error("could not read the DKIM private key: {0}")]
    BadKey(String),
    /// The signer rejected the message or configuration.
    #[error("could not sign: {0}")]
    Signing(String),
}

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
/// [`SignError::BadKey`] for an unreadable key, [`SignError::Signing`]
/// when the signer refuses. Both mean: fix configuration, don't send.
pub fn dkim_sign(
    message: &Message,
    domain: &str,
    selector: &str,
    rsa_private_key_pem: &str,
) -> Result<Message, SignError> {
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
        .map_err(|e| SignError::BadKey(e.to_string()))?;
    let key =
        RsaKey::<Sha256>::from_key_der(key_der).map_err(|e| SignError::BadKey(e.to_string()))?;

    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(message.raw())
        .map_err(|e| SignError::Signing(e.to_string()))?;

    let mut sealed = signature.to_header().into_bytes();
    sealed.extend_from_slice(message.raw());
    Ok(Message::from_raw(sealed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway 2048-bit key generated for these tests only — its
    /// private half lives in a public repo, so it must never sign real
    /// mail. (2048 is also the floor the crypto backend enforces, and the
    /// production standard for DKIM.)
    const TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAslYW5+62eTeuYabVNJNDqdrerunNqpjKSC8a4VsMypsvQHFl
p3Mi75mUVFw341oKP2RqheNxI27mE4EDjrrpL0P5YaBugxKiZcW03LGjqqrUQZhV
mROkENOx2IfS2Wu9Q/88Ixg89HWWWencTkCQ5DNwvzi6JWvMYEql/amiePoardz8
Pe9iHJO6HhxqOGjE6IuMOu4hbbhkgB1YeRFszOZHPiWqaMprmWqToMoCXLXwxaeX
4hCQgRu7REqSFePcAM5d+Rcp3gGRzdALBBr5NXML2e6t5v+2lhsR847gRCwo178x
DEqoyom395oWQcfZmz7KmGs2tNkcCrxDhiHQ8QIDAQABAoIBADC0BiltLfRI2pzc
nRlwpmf62BnYzEws0gGIq8SjwwiJ/QuSbHqgnQfmX3XygWjbrDTHzbem97z/imIF
N92A+jHoVHDvCX9OVX+J0Oz8rn/ri3AmlCnsDUBzL/y8iz7Jh7TMPbYv5mW0v0zq
6zmLtIY97iqq6VtS50vc1xxBeZej8XL0dxRnOodWWeNYy+r2sGNUfSIlaNPxq9jU
73hJHBcgEieQWdA0Si7tcmD1z5akS6t/LOZfLtZkTm5/3HQ2DNo0QAuKaMdFZ3ti
jE4wiIzaK92c9nSFlyNffTVnYukpbVAA/GAYvMj1VFCofK9gqLew1V1PMcXEUduI
0OzWGmkCgYEA19dU0qTdYtaaSpxUJZEGCuXdya9rAk1SR8fTkx+h4skILXq7p3Bz
Jx3voGWYmG5a3IEQcnFc3xV11qFzyceQBIMBT6Ks8CH+8mm+2U+59TPLEAkDv27Z
vaP3MU/4qFrQPkl48ViRAQ2p2KegCWIgF8WLWiHqpovAHo4FS8T6mF8CgYEA04Rg
BuoUYwQqrbOw4Of/ySvyCYI8ZGu9y1O5lu6cTZDslfpq0k1qUF2Bgs06C401qEf7
hV1ONVTVDbQc+CKUtMm8UU74gorrNjF9iBX49oqkgxIoSqWh0KdwgZER4Uh4kr3m
aVZzsxlUSGJqoF72vQ1u02HebzEp0PLoR2ZtWK8CgYEAkAFFwYhngIMny/HDHpFE
k87Li71yysVlyShkW7t2GcYAo79IJi2bVpTdhIlkJwcxrf6aR5Ck4t4BkeKESzLP
PoNdQ5GIimpUG847m+dabWNR7u/kxTsjISidSxRNFZ4JZBVHENcDX82K7VbhKoGC
YfnVwJvyX43L71bX57aTb0cCgYAoKzWJWp7whvQL9NocfDKpY70dbSxG7ecnXAkc
zsfEO0eS2/G5apZMGNXln0/sra6I/NKZazTVD/0+EvyFaxvOkZk/3712HSe6LP/n
/jQ/rei8M5CPTJFEbOgC0ygQHpE3XPULAC4MzzygWoBhYGd/U7O+VRHHEBEe62KN
XLhbZQKBgGZGbjEzm8dHxw2osQf37kPp56y2szBq+iJmZGpLBtI2k52mSFDC9H/G
QWDxpqDqooxVoQ+v0MFzOyniSmSqnYFULcY5+rmpUgltmRaNyxK45T/zMeDkmPbr
rvQERp5skEmgHlqdF5DxwGtBjMmcegOUjAWLZAWOiU4NDl1/NgLK
-----END RSA PRIVATE KEY-----"#;

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

    /// The SAME throwaway key as [`TEST_KEY`], but in PKCS#8 form
    /// (`BEGIN PRIVATE KEY`) — what OpenSSL 3 writes by default. Both
    /// containers must work; "regenerate your key in the other format"
    /// is not an answer a mail engine gets to give.
    const TEST_KEY_PKCS8: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyVhbn7rZ5N65h
ptU0k0Op2t6u6c2qmMpILxrhWwzKmy9AcWWncyLvmZRUXDfjWgo/ZGqF43EjbuYT
gQOOuukvQ/lhoG6DEqJlxbTcsaOqqtRBmFWZE6QQ07HYh9LZa71D/zwjGDz0dZZZ
6dxOQJDkM3C/OLola8xgSqX9qaJ4+hqt3Pw972Ick7oeHGo4aMToi4w67iFtuGSA
HVh5EWzM5kc+JapoymuZapOgygJctfDFp5fiEJCBG7tESpIV49wAzl35FyneAZHN
0AsEGvk1cwvZ7q3m/7aWGxHzjuBELCjXvzEMSqjKibf3mhZBx9mbPsqYaza02RwK
vEOGIdDxAgMBAAECggEAMLQGKW0t9EjanNydGXCmZ/rYGdjMTCzSAYirxKPDCIn9
C5JseqCdB+ZfdfKBaNusNMfNt6b3vP+KYgU33YD6MehUcO8Jf05Vf4nQ7Pyuf+uL
cCaUKewNQHMv/LyLPsmHtMw9ti/mZbS/TOrrOYu0hj3uKqrpW1LnS9zXHEF5l6Px
cvR3FGc6h1ZZ41jL6vawY1R9IiVo0/Gr2NTveEkcFyASJ5BZ0DRKLu1yYPXPlqRL
q38s5l8u1mRObn/cdDYM2jRAC4pox0Vne2KMTjCIjNor3Zz2dIWXI199NWdi6Slt
UAD8YBi8yPVUUKh8r2Cot7DVXU8xxcRR24jQ7NYaaQKBgQDX11TSpN1i1ppKnFQl
kQYK5d3Jr2sCTVJHx9OTH6HiyQgteruncHMnHe+gZZiYblrcgRBycVzfFXXWoXPJ
x5AEgwFPoqzwIf7yab7ZT7n1M8sQCQO/btm9o/cxT/ioWtA+SXjxWJEBDanYp6AJ
YiAXxYtaIeqmi8AejgVLxPqYXwKBgQDThGAG6hRjBCqts7Dg5//JK/IJgjxka73L
U7mW7pxNkOyV+mrSTWpQXYGCzToLjTWoR/uFXU41VNUNtBz4IpS0ybxRTviCius2
MX2IFfj2iqSDEihKpaHQp3CBkRHhSHiSveZpVnOzGVRIYmqgXva9DW7TYd5vMSnQ
8uhHZm1YrwKBgQCQAUXBiGeAgyfL8cMekUSTzsuLvXLKxWXJKGRbu3YZxgCjv0gm
LZtWlN2EiWQnBzGt/ppHkKTi3gGR4oRLMs8+g11DkYiKalQbzjub51ptY1Hu7+TF
OyMhKJ1LFE0VnglkFUcQ1wNfzYrtVuEqgYJh+dXAm/JfjcvvVtfntpNvRwKBgCgr
NYlanvCG9Av02hx8MqljvR1tLEbt5ydcCRzOx8Q7R5Lb8blqlkwY1eWfT+ytroj8
0plrNNUP/T4S/IVrG86RmT/fvXYdJ7os/+f+ND+t6LwzkI9MkURs6ALTKBAekTdc
9QsALgzPPKBagGFgZ39Ts75VEccQER7rYo1cuFtlAoGAZkZuMTObx0fHDaixB/fu
Q+nnrLazMGr6ImZkaksG0jaTnaZIUML0f8ZBYPGmoOqijFWhD6/QwXM7KeJKZKqd
gVQtxjn6ualSCW2ZFo3LErjlP/Mx4OSY9uuu9ARGnmyQSaAeWp0XkPHAa0GMyZx6
A5SMBYtkBY6JTg0OXX82Aso=
-----END PRIVATE KEY-----"#;

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
        assert!(matches!(err, SignError::BadKey(_)));
    }
}
