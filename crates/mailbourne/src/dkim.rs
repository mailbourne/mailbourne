//! # dkim — mint keys, derive the record
//!
//! DKIM key *management*, distinct from the two things that use it: signing
//! an outgoing message (that's [`out::sign`](crate::out::sign), which needs
//! the full crypto-over-the-wire stack) and checking what DNS actually serves
//! (that's the inspector). Minting a keypair and deriving its publishable
//! `v=DKIM1; …` record need only pure-Rust RSA — no network, no TLS — so they
//! live here, always available, and the inspector can judge your DKIM without
//! pulling in the sender.
//!
//! The cryptography rides RustCrypto's `rsa`; we never hand-roll it.

/// Why a DKIM key operation failed. Both variants mean a configuration
/// problem — a bad key or a failed mint — never a mail problem.
#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    /// The private key could not be read (not a PEM-encoded RSA key in
    /// either PKCS#1 or PKCS#8 form).
    #[error("could not read the DKIM private key: {0}")]
    BadKey(String),
    /// Key generation or encoding failed.
    #[error("dkim key error: {0}")]
    Signing(String),
}

/// A freshly minted DKIM identity: keep the private half, publish the
/// public half.
#[derive(Debug)]
pub struct DkimKeypair {
    /// The private key, PKCS#8 PEM. Write it to disk with tight
    /// permissions; it must never leave the machine.
    pub private_key_pem: String,
    /// The ready-to-paste DNS TXT record value:
    /// `v=DKIM1; k=rsa; p=<base64 public key>`.
    pub dns_record_value: String,
}

/// Mints a fresh 2048-bit RSA DKIM keypair.
///
/// 2048 bits is the DKIM production standard (and the floor our signing
/// backend enforces). The returned [`DkimKeypair`] carries both halves of
/// the deal: the secret you keep and the record you publish at
/// `<selector>._domainkey.<domain>`.
///
/// # Errors
/// [`DkimError::Signing`] if key generation itself fails (exotic —
/// effectively only under RNG failure).
pub fn generate_dkim_keypair() -> Result<DkimKeypair, DkimError> {
    use base64::Engine;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    let mut rng = rand::thread_rng();
    let private =
        rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|e| DkimError::Signing(e.to_string()))?;

    let private_key_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| DkimError::Signing(e.to_string()))?
        .to_string();

    // The DNS `p=` value is the base64 of the SPKI DER — the same bytes
    // `openssl rsa -pubout -outform DER` would emit.
    let spki = rsa::RsaPublicKey::from(&private)
        .to_public_key_der()
        .map_err(|e| DkimError::Signing(e.to_string()))?;
    let p = base64::engine::general_purpose::STANDARD.encode(spki.as_bytes());

    Ok(DkimKeypair {
        private_key_pem,
        dns_record_value: format!("v=DKIM1; k=rsa; p={p}"),
    })
}

/// Recovers the publishable DNS record from an existing private key —
/// the same `v=DKIM1; k=rsa; p=…` line [`generate_dkim_keypair`] hands out,
/// but derived from a key you already have (either PEM container).
///
/// This is what lets `domain show` print the DKIM row from the key on
/// disk, and what lets the inspector catch the classic silent failure:
/// a key that no longer matches the record DNS is serving.
///
/// # Errors
/// [`DkimError::BadKey`] when the PEM can't be read as an RSA key.
pub fn public_record_for(private_key_pem: &str) -> Result<String, DkimError> {
    use base64::Engine;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

    // Either envelope: PKCS#8 ("BEGIN PRIVATE KEY") or PKCS#1
    // ("BEGIN RSA PRIVATE KEY") — same key inside.
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(private_key_pem))
        .map_err(|e| DkimError::BadKey(e.to_string()))?;

    let spki = rsa::RsaPublicKey::from(&private)
        .to_public_key_der()
        .map_err(|e| DkimError::Signing(e.to_string()))?;
    let p = base64::engine::general_purpose::STANDARD.encode(spki.as_bytes());
    Ok(format!("v=DKIM1; k=rsa; p={p}"))
}

/// A throwaway 2048-bit key generated for tests only — its private half
/// lives in a public repo, so it must never sign real mail. (2048 is also
/// the floor the crypto backend enforces, and the production standard for
/// DKIM.) Shared with [`out::sign`](crate::out::sign)'s signing tests.
#[cfg(test)]
pub(crate) const TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
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

/// The SAME throwaway key as [`TEST_KEY`], but in PKCS#8 form
/// (`BEGIN PRIVATE KEY`) — what OpenSSL 3 writes by default. Both containers
/// must work; "regenerate your key in the other format" is not an answer a
/// mail engine gets to give.
#[cfg(test)]
pub(crate) const TEST_KEY_PKCS8: &str = r#"-----BEGIN PRIVATE KEY-----
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_record_is_recovered_from_a_private_key() {
        let pair = generate_dkim_keypair().unwrap();
        let recovered = public_record_for(&pair.private_key_pem).unwrap();
        assert_eq!(recovered, pair.dns_record_value);
    }

    #[test]
    fn recovery_works_for_the_pkcs1_container_too() {
        // TEST_KEY (PKCS#1) and TEST_KEY_PKCS8 hold the same key — the
        // recovered record must be identical from either envelope.
        let a = public_record_for(TEST_KEY).unwrap();
        let b = public_record_for(TEST_KEY_PKCS8).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("v=DKIM1; k=rsa; p="));
    }

    #[test]
    fn garbage_is_refused_as_a_bad_key() {
        assert!(matches!(
            public_record_for("not a key"),
            Err(DkimError::BadKey(_))
        ));
    }

    #[test]
    fn the_dns_record_value_is_ready_to_paste() {
        let pair = generate_dkim_keypair().unwrap();
        assert!(pair.dns_record_value.starts_with("v=DKIM1; k=rsa; p="));
        // A 2048-bit SPKI in base64 is ~392 chars; anything short means
        // we encoded the wrong thing.
        let p = pair.dns_record_value.rsplit("p=").next().unwrap();
        assert!(
            p.len() > 300,
            "public key looks truncated: {} chars",
            p.len()
        );
    }

    #[test]
    fn every_minting_is_unique() {
        let a = generate_dkim_keypair().unwrap();
        let b = generate_dkim_keypair().unwrap();
        assert_ne!(a.private_key_pem, b.private_key_pem);
    }
}
