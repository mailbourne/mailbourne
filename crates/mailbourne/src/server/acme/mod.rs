//! # acme — mailbourne's own certbot
//!
//! Provisions a real TLS certificate from an ACME certificate authority (Let's
//! Encrypt) so STARTTLS is trusted by clients that verify it — the piece that
//! makes "point Gmail's send-as at mailbourne" turnkey, with no external
//! certbot and no OpenSSL. It's the single-static-binary promise applied to
//! certificates.
//!
//! Built up in pieces:
//! - [`account`] — the account key and JWS signing (the crypto core);
//! - HTTP-01 challenge handling, the order flow, and the `cert` command land
//!   on top of it.
//!
//! Design (see the roadmap): HTTP-01 first (no credentials — mailbourne just
//! answers a token on port 80); DNS-01 (a least-privilege Cloudflare token)
//! later. Testing uses Let's Encrypt's staging endpoint until the flow is
//! proven, so production rate limits are never burned.

pub mod account;
pub mod challenge;
pub mod http;
pub mod order;
