//! # acme::order — the certificate order flow
//!
//! The orchestration that turns an account key + a domain into a certificate,
//! driving the whole RFC 8555 conversation: fetch the directory, register the
//! account, place an order, answer the HTTP-01 challenge (via a
//! [`Http01Solver`], so *how* the token is served — a port-80 responder — is
//! someone else's job), poll to `valid`, finalize with a CSR, and download the
//! PEM chain.
//!
//! Every request is a JWS ([`account`](super::account)) carried over HTTPS
//! ([`http`](super::http)); each response's `Replay-Nonce` seeds the next.

use super::account::{AccountKey, AcmeCryptoError, KeyId};
use super::http;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::Value;
use std::time::Duration;

/// Let's Encrypt's production directory (real, trusted certificates).
pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt's staging directory (untrusted certs, generous rate limits —
/// use it until the flow is proven).
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Why obtaining a certificate failed.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// A signing / key operation failed.
    #[error("acme key error: {0}")]
    Crypto(String),
    /// A network or TLS failure talking to the CA.
    #[error("acme network error: {0}")]
    Http(#[from] std::io::Error),
    /// The CA said something we couldn't use (unexpected status or JSON), or
    /// the challenge never validated.
    #[error("acme protocol error: {0}")]
    Protocol(String),
}

impl From<AcmeCryptoError> for AcmeError {
    fn from(e: AcmeCryptoError) -> Self {
        AcmeError::Crypto(e.to_string())
    }
}

/// Serves an HTTP-01 challenge: makes `key_authorization` retrievable at
/// `/.well-known/acme-challenge/<token>` for as long as validation needs it.
#[async_trait]
pub trait Http01Solver: Send + Sync {
    /// Present the answer for `token` before the CA is told to validate.
    async fn present(&self, token: &str, key_authorization: &str);
    /// Optional teardown once the challenge is done.
    async fn cleanup(&self, _token: &str) {}
}

/// A freshly issued certificate: the PEM chain and its private key.
pub struct Certificate {
    /// The certificate chain (leaf first), PEM.
    pub cert_pem: String,
    /// The certificate's private key, PEM.
    pub key_pem: String,
}

/// The directory endpoints we use.
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// Obtains a certificate for `domains` from the ACME `directory_url`, answering
/// challenges through `solver`.
///
/// # Errors
/// [`AcmeError`] on any signing, network, or protocol failure, or if a
/// challenge never reaches `valid`.
pub async fn obtain(
    directory_url: &str,
    account: &AccountKey,
    contact_email: Option<&str>,
    domains: &[String],
    solver: &dyn Http01Solver,
) -> Result<Certificate, AcmeError> {
    let dir = directory(directory_url).await?;
    let mut nonce = fresh_nonce(&dir.new_nonce).await?;

    // Register (or re-use) the account; the CA returns our account URL (kid).
    let payload = match contact_email {
        Some(email) => {
            format!(r#"{{"termsOfServiceAgreed":true,"contact":["mailto:{email}"]}}"#)
        }
        None => r#"{"termsOfServiceAgreed":true}"#.to_string(),
    };
    let jws = account.signed_request(&dir.new_account, &nonce, &payload, KeyId::Jwk)?;
    let resp = http::post(&dir.new_account, "application/jose+json", jws.as_bytes()).await?;
    if resp.status != 200 && resp.status != 201 {
        return Err(AcmeError::Protocol(format!(
            "newAccount failed ({}): {}",
            resp.status,
            resp.text()
        )));
    }
    let kid = resp
        .header("location")
        .ok_or_else(|| AcmeError::Protocol("newAccount returned no account URL".into()))?
        .to_string();
    nonce = take_nonce(&resp, nonce);

    // Place the order for the domains.
    let identifiers: Vec<String> = domains
        .iter()
        .map(|d| format!(r#"{{"type":"dns","value":"{d}"}}"#))
        .collect();
    let order_payload = format!(r#"{{"identifiers":[{}]}}"#, identifiers.join(","));
    let (order, order_url, mut nonce) =
        post_json(account, &dir.new_order, &order_payload, &kid, nonce).await?;
    if order_url.is_empty() {
        return Err(AcmeError::Protocol("newOrder returned no order URL".into()));
    }

    // Answer each authorization's HTTP-01 challenge.
    let authorizations = order["authorizations"]
        .as_array()
        .ok_or_else(|| AcmeError::Protocol("order has no authorizations".into()))?
        .clone();
    for authz_url in &authorizations {
        let url = authz_url
            .as_str()
            .ok_or_else(|| AcmeError::Protocol("authorization url not a string".into()))?;
        let (authz, _, n) = post_as_get(account, url, &kid, nonce).await?;
        nonce = n;

        let (challenge_url, token) = http01_challenge(&authz)?;
        let key_authorization = account.key_authorization(&token);
        solver.present(&token, &key_authorization).await;

        // Tell the CA the challenge is ready, then poll until it validates.
        let (_, _, n) = post_json(account, &challenge_url, "{}", &kid, nonce).await?;
        nonce = n;
        nonce = poll_until_valid(account, url, &kid, nonce).await?;
        solver.cleanup(&token).await;
    }

    // Finalize with a CSR, poll the order to `valid`, download the chain.
    let finalize_url = order["finalize"]
        .as_str()
        .ok_or_else(|| AcmeError::Protocol("order has no finalize url".into()))?;
    let (csr_der, key_pem) = make_csr(domains)?;
    let finalize_payload = format!(r#"{{"csr":"{}"}}"#, B64URL.encode(&csr_der));
    let (_, _, mut nonce) =
        post_json(account, finalize_url, &finalize_payload, &kid, nonce).await?;

    // Poll the order itself until it carries a certificate URL.
    let cert_url = poll_for_certificate(account, &order_url, &kid, &mut nonce).await?;

    let (cert_resp, _, _) = post_as_get_raw(account, &cert_url, &kid, nonce).await?;
    if cert_resp.status != 200 {
        return Err(AcmeError::Protocol(format!(
            "certificate download failed ({})",
            cert_resp.status
        )));
    }
    Ok(Certificate {
        cert_pem: cert_resp.text().into_owned(),
        key_pem,
    })
}

/// Fetches and parses the ACME directory.
async fn directory(url: &str) -> Result<Directory, AcmeError> {
    let resp = http::get(url).await?;
    let v: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| AcmeError::Protocol(format!("bad directory JSON: {e}")))?;
    let field = |name: &str| {
        v[name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| AcmeError::Protocol(format!("directory missing {name}")))
    };
    Ok(Directory {
        new_nonce: field("newNonce")?,
        new_account: field("newAccount")?,
        new_order: field("newOrder")?,
    })
}

/// Gets a fresh anti-replay nonce.
async fn fresh_nonce(new_nonce_url: &str) -> Result<String, AcmeError> {
    let resp = http::get(new_nonce_url).await?;
    resp.header("replay-nonce")
        .map(str::to_string)
        .ok_or_else(|| AcmeError::Protocol("newNonce returned no Replay-Nonce".into()))
}

/// The next nonce from a response, falling back to `previous` if absent.
fn take_nonce(resp: &http::Response, previous: String) -> String {
    resp.header("replay-nonce")
        .map(str::to_string)
        .unwrap_or(previous)
}

/// A signed POST expecting a JSON body; returns `(json, Location, next_nonce)`.
async fn post_json(
    account: &AccountKey,
    url: &str,
    payload: &str,
    kid: &str,
    nonce: String,
) -> Result<(Value, String, String), AcmeError> {
    let jws = account.signed_request(url, &nonce, payload, KeyId::Kid(kid))?;
    let resp = http::post(url, "application/jose+json", jws.as_bytes()).await?;
    let next = take_nonce(&resp, nonce);
    if resp.status >= 400 {
        return Err(AcmeError::Protocol(format!(
            "{url} failed ({}): {}",
            resp.status,
            resp.text()
        )));
    }
    let location = resp.header("location").unwrap_or_default().to_string();
    let json: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| AcmeError::Protocol(format!("bad JSON from {url}: {e}")))?;
    Ok((json, location, next))
}

/// A POST-as-GET (authenticated read) returning parsed JSON.
async fn post_as_get(
    account: &AccountKey,
    url: &str,
    kid: &str,
    nonce: String,
) -> Result<(Value, String, String), AcmeError> {
    let (resp, location, next) = post_as_get_raw(account, url, kid, nonce).await?;
    let json: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| AcmeError::Protocol(format!("bad JSON from {url}: {e}")))?;
    Ok((json, location, next))
}

/// A POST-as-GET returning the raw response (for the cert PEM).
async fn post_as_get_raw(
    account: &AccountKey,
    url: &str,
    kid: &str,
    nonce: String,
) -> Result<(http::Response, String, String), AcmeError> {
    let jws = account.signed_request(url, &nonce, "", KeyId::Kid(kid))?;
    let resp = http::post(url, "application/jose+json", jws.as_bytes()).await?;
    let next = take_nonce(&resp, nonce);
    let location = resp.header("location").unwrap_or_default().to_string();
    Ok((resp, location, next))
}

/// The HTTP-01 challenge `(url, token)` from an authorization object.
fn http01_challenge(authz: &Value) -> Result<(String, String), AcmeError> {
    let challenges = authz["challenges"]
        .as_array()
        .ok_or_else(|| AcmeError::Protocol("authorization has no challenges".into()))?;
    for challenge in challenges {
        if challenge["type"] == "http-01" {
            let url = challenge["url"]
                .as_str()
                .ok_or_else(|| AcmeError::Protocol("challenge has no url".into()))?;
            let token = challenge["token"]
                .as_str()
                .ok_or_else(|| AcmeError::Protocol("challenge has no token".into()))?;
            return Ok((url.to_string(), token.to_string()));
        }
    }
    Err(AcmeError::Protocol("no http-01 challenge offered".into()))
}

/// Polls an authorization until it's `valid`, or errors if it goes `invalid`.
async fn poll_until_valid(
    account: &AccountKey,
    authz_url: &str,
    kid: &str,
    mut nonce: String,
) -> Result<String, AcmeError> {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (authz, _, n) = post_as_get(account, authz_url, kid, nonce).await?;
        nonce = n;
        match authz["status"].as_str() {
            Some("valid") => return Ok(nonce),
            Some("invalid") => {
                return Err(AcmeError::Protocol(format!(
                    "challenge failed: {}",
                    authz["challenges"]
                )));
            }
            _ => continue, // still pending/processing
        }
    }
    Err(AcmeError::Protocol("challenge validation timed out".into()))
}

/// Polls the order until it's `valid` and returns its certificate URL.
async fn poll_for_certificate(
    account: &AccountKey,
    order_url: &str,
    kid: &str,
    nonce: &mut String,
) -> Result<String, AcmeError> {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (order, _, n) = post_as_get(account, order_url, kid, nonce.clone()).await?;
        *nonce = n;
        match order["status"].as_str() {
            Some("valid") => {
                return order["certificate"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| {
                        AcmeError::Protocol("valid order has no certificate url".into())
                    });
            }
            Some("invalid") => return Err(AcmeError::Protocol("order became invalid".into())),
            _ => continue,
        }
    }
    Err(AcmeError::Protocol("order finalization timed out".into()))
}

/// Generates a certificate keypair and a CSR (DER) for `domains`.
fn make_csr(domains: &[String]) -> Result<(Vec<u8>, String), AcmeError> {
    let params = rcgen::CertificateParams::new(domains.to_vec())
        .map_err(|e| AcmeError::Crypto(format!("csr params: {e}")))?;
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| AcmeError::Crypto(format!("csr key: {e}")))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| AcmeError::Crypto(format!("csr: {e}")))?;
    Ok((csr.der().to_vec(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http01_is_picked_out_of_the_challenge_list() {
        let authz: Value = serde_json::from_str(
            r#"{
                "status":"pending",
                "challenges":[
                    {"type":"dns-01","url":"https://ca/dns","token":"nope"},
                    {"type":"http-01","url":"https://ca/http","token":"tok42"}
                ]
            }"#,
        )
        .unwrap();
        let (url, token) = http01_challenge(&authz).unwrap();
        assert_eq!(url, "https://ca/http");
        assert_eq!(token, "tok42");
    }

    #[test]
    fn an_authorization_without_http01_is_a_protocol_error() {
        let authz: Value =
            serde_json::from_str(r#"{"challenges":[{"type":"dns-01","url":"u","token":"t"}]}"#)
                .unwrap();
        assert!(matches!(
            http01_challenge(&authz),
            Err(AcmeError::Protocol(_))
        ));
    }

    #[test]
    fn a_csr_is_generated_for_the_domains() {
        let (der, key_pem) = make_csr(&["mail.ours.test".to_string()]).unwrap();
        assert!(!der.is_empty(), "CSR DER produced");
        assert!(
            key_pem.contains("PRIVATE KEY"),
            "a private key PEM produced"
        );
    }
}
