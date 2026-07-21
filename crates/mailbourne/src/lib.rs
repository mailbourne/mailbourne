//! # mailbourne — the face
//!
//! A Rust-native mail server and library — single binary, built-in doctor
//! for DNS, DKIM, and deliverability.
//!
//! This facade crate is the one public name: the `mailbourne` binary for
//! operators, and the unified high-level interface for applications
//! embedding mail. Everything underneath lives in focused internal crates —
//! see `ARCHITECTURE.md` for the reading order, starting with
//! `mailbourne-out` ("a message must leave").
//!
//! Current state: the outbound path works end to end — compose, DKIM-sign,
//! route by MX, dial with STARTTLS, speak the dialogue, classify the
//! outcome. The builder facade (`Mailbourne::builder()`), inbound, and the
//! doctor arrive next.

pub mod compose;

pub use mailbourne_core::{EmailAddress, Envelope, MailEvent, Message};
pub use mailbourne_out as out;

/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
