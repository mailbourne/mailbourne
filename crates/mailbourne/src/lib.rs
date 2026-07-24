//! # mailbourne — the face
//!
//! A liveable mail server and library — single binary, built-in inspector
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
//! inspector arrive next.

pub mod compose;
pub mod console;
pub mod identity;
pub mod inspect;
pub mod route;
pub mod serve;
pub mod sheet;

pub use mailbourne_core::config;
pub use mailbourne_core::{EmailAddress, Envelope, MailEvent, Message};
pub use mailbourne_in as inbound;
pub use mailbourne_out as out;
pub use mailbourne_policy as policy;
pub use mailbourne_probe as probe;
pub use mailbourne_store as store;

/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
