//! # wings — the three sections of the checklist
//!
//! Mail has two directions of trust, plus the shared identity both stand on:
//!
//! - [`identity`] — who am I? (domain, hostname, TLS, DNS provider)
//! - [`send`] — will the world trust my mail? (port 25 out, PTR, SPF, DKIM,
//!   DMARC, blocklists, and the ★ send-proof)
//! - [`receive`] — can the world reach me? (MX, port 25 in, MTA-STS, and
//!   the ★ receive-proof)

pub mod identity;
pub mod receive;
pub mod send;
