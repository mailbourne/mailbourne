//! # acme::account — the ACME account key and JWS signing
//!
//! Every request to a CA like Let's Encrypt is a **JWS** (JSON Web Signature)
//! signed with a long-lived *account* key — distinct from the certificate key.
//! This owns that key and the three things built from it:
//!
//! - the **JWK** (the public key as JSON) sent when first registering;
//! - the **thumbprint** (RFC 7638), which forms the key-authorization a
//!   challenge is answered with;
//! - the **signed request** body every ACME call is wrapped in.
//!
//! RS256 (RSA + SHA-256) — the same pure-Rust `rsa` (and its SHA-256) the rest
//! of the engine uses, so nothing here reaches for a system library.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::sha2::{Digest, Sha256};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

/// Why an ACME crypto operation failed.
#[derive(Debug, thiserror::Error)]
pub enum AcmeCryptoError {
    /// Key generation, parsing, or signing failed.
    #[error("acme key error: {0}")]
    Key(String),
}

/// How a request identifies its signer: by full public key (first contact)
/// or by the account URL the CA assigned (everything after).
pub enum KeyId<'a> {
    /// Include the full JWK — used only for `newAccount`.
    Jwk,
    /// Reference the account URL (`kid`) — every subsequent request.
    Kid(&'a str),
}

/// The ACME account key: an RSA keypair that signs every request.
pub struct AccountKey {
    key: RsaPrivateKey,
}

impl AccountKey {
    /// Mints a fresh 2048-bit account key.
    ///
    /// # Errors
    /// [`AcmeCryptoError::Key`] if key generation fails (effectively only on
    /// RNG failure).
    pub fn generate() -> Result<Self, AcmeCryptoError> {
        let mut rng = rand::thread_rng();
        let key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AcmeCryptoError::Key(e.to_string()))?;
        Ok(Self { key })
    }

    /// Loads an account key from PKCS#8 PEM (as [`to_pem`](Self::to_pem) wrote).
    ///
    /// # Errors
    /// [`AcmeCryptoError::Key`] if the PEM isn't a readable RSA key.
    pub fn from_pem(pem: &str) -> Result<Self, AcmeCryptoError> {
        RsaPrivateKey::from_pkcs8_pem(pem)
            .map(|key| Self { key })
            .map_err(|e| AcmeCryptoError::Key(e.to_string()))
    }

    /// Serializes the account key to PKCS#8 PEM, to persist between runs.
    ///
    /// # Errors
    /// [`AcmeCryptoError::Key`] if encoding fails.
    pub fn to_pem(&self) -> Result<String, AcmeCryptoError> {
        self.key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| AcmeCryptoError::Key(e.to_string()))
    }

    /// The public modulus, base64url (no padding).
    fn n(&self) -> String {
        B64URL.encode(self.key.to_public_key().n().to_bytes_be())
    }

    /// The public exponent, base64url (no padding).
    fn e(&self) -> String {
        B64URL.encode(self.key.to_public_key().e().to_bytes_be())
    }

    /// The public key as a JWK, for the `newAccount` request.
    pub fn jwk(&self) -> serde_json::Value {
        serde_json::json!({ "kty": "RSA", "n": self.n(), "e": self.e() })
    }

    /// The RFC 7638 thumbprint: base64url(SHA-256 of the canonical JWK).
    pub fn thumbprint(&self) -> String {
        // Canonical form: members lexicographically ordered, no whitespace.
        let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, self.e(), self.n());
        B64URL.encode(Sha256::digest(canonical.as_bytes()))
    }

    /// The key authorization for a challenge `token`: `token.thumbprint`. For
    /// HTTP-01 this is served verbatim at the well-known challenge path.
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    /// An RS256 signature (base64url) over `signing_input`.
    fn sign(&self, signing_input: &str) -> Result<String, AcmeCryptoError> {
        let digest = Sha256::digest(signing_input.as_bytes());
        let signature = self
            .key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| AcmeCryptoError::Key(e.to_string()))?;
        Ok(B64URL.encode(signature))
    }

    /// Builds the flattened JWS to POST for one ACME request: `url` is the
    /// endpoint, `nonce` the anti-replay token, `payload` the JSON body (or
    /// `""` for a POST-as-GET), and `key_id` how we identify ourselves.
    ///
    /// # Errors
    /// [`AcmeCryptoError::Key`] if signing fails.
    pub fn signed_request(
        &self,
        url: &str,
        nonce: &str,
        payload: &str,
        key_id: KeyId<'_>,
    ) -> Result<String, AcmeCryptoError> {
        let protected = match key_id {
            KeyId::Jwk => {
                serde_json::json!({ "alg": "RS256", "nonce": nonce, "url": url, "jwk": self.jwk() })
            }
            KeyId::Kid(kid) => {
                serde_json::json!({ "alg": "RS256", "nonce": nonce, "url": url, "kid": kid })
            }
        };
        let protected_b64 = B64URL.encode(protected.to_string().as_bytes());
        let payload_b64 = B64URL.encode(payload.as_bytes());
        let signature = self.sign(&format!("{protected_b64}.{payload_b64}"))?;
        Ok(serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature,
        })
        .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thumbprint_is_stable_and_url_safe() {
        let key = AccountKey::generate().unwrap();
        let a = key.thumbprint();
        assert_eq!(a, key.thumbprint(), "same key → same thumbprint");
        // base64url: no '+', '/', or '=' padding.
        assert!(!a.contains('+') && !a.contains('/') && !a.contains('='));
        assert_eq!(key.key_authorization("tok"), format!("tok.{a}"));
    }

    #[test]
    fn the_key_survives_a_pem_round_trip() {
        let key = AccountKey::generate().unwrap();
        let pem = key.to_pem().unwrap();
        let reloaded = AccountKey::from_pem(&pem).unwrap();
        assert_eq!(
            key.thumbprint(),
            reloaded.thumbprint(),
            "same key after reload"
        );
    }

    #[test]
    fn a_signed_request_carries_the_right_header_and_verifies() {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;

        let key = AccountKey::generate().unwrap();
        let jws = key
            .signed_request("https://acme.test/order", "nonce123", "{}", KeyId::Jwk)
            .unwrap();
        let jws: serde_json::Value = serde_json::from_str(&jws).unwrap();

        // The protected header names RS256, the nonce, the url, and a JWK.
        let protected_b64 = jws["protected"].as_str().unwrap();
        let protected: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(protected_b64).unwrap()).unwrap();
        assert_eq!(protected["alg"], "RS256");
        assert_eq!(protected["nonce"], "nonce123");
        assert_eq!(protected["url"], "https://acme.test/order");
        assert_eq!(protected["jwk"]["kty"], "RSA");

        // The signature verifies over `protected.payload` with the public key.
        let signing_input = format!("{protected_b64}.{}", jws["payload"].as_str().unwrap());
        let sig = Signature::try_from(
            B64URL
                .decode(jws["signature"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let verifying = VerifyingKey::<Sha256>::new(key.key.to_public_key());
        assert!(verifying.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn kid_requests_reference_the_account_url_not_a_jwk() {
        let key = AccountKey::generate().unwrap();
        let jws = key
            .signed_request(
                "https://acme.test/finalize",
                "n2",
                "{}",
                KeyId::Kid("https://acme.test/acct/1"),
            )
            .unwrap();
        let jws: serde_json::Value = serde_json::from_str(&jws).unwrap();
        let protected: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(jws["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(protected["kid"], "https://acme.test/acct/1");
        assert!(protected.get("jwk").is_none(), "kid requests carry no jwk");
    }
}
