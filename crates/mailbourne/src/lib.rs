//! # mailbourne — a liveable mail server and library
//!
//! A liveable mail server and library — a single crate, a single binary,
//! with a built-in inspector for DNS, DKIM, and deliverability.
//!
//! `mailbourne` is one published crate: the binary for operators, and the
//! embeddable library for applications that want to send or receive mail.
//! What used to be a workspace of `mailbourne-*` packages now lives here as
//! modules — read them in dependency order, starting with [`out`]
//! ("a message must leave"):
//!
//! - `core` — the shared vocabulary: addresses, envelopes, messages, config
//! - `out` — the outbound path: compose, DKIM-sign, route by MX, dial, speak
//! - `inbound` — the server side of SMTP (receiving)
//! - `policy` — who we accept mail for (never an open relay)
//! - `store` — where received mail lands (Maildir)
//! - `spool` — the durable queue: accepted before `250`, delivered by a worker
//! - `probe` / `checklist` — gather live DNS evidence and judge it
//! - `route`, `serve`, `worker` — glue: targets, the daemon, delivery
//!
//! ## Compose what you embed
//!
//! Pull only the capability you need — the rest (and its dependencies) never
//! compiles:
//!
//! ```toml
//! # Just send mail:
//! mailbourne = { version = "0.0.4", default-features = false, features = ["send"] }
//! # Run a receiving server (implies `send`):
//! mailbourne = { version = "0.0.4", default-features = false, features = ["server"] }
//! ```
//!
//! Features: `send` (outbound engine) · `server` (receive + spool + deliver,
//! implies `send`) · `inspect` (DNS/deliverability checks) · `cli` (the
//! operator binary + console; the default). Reach for what you need —
//! `mailbourne::out::send`, `mailbourne::serve::run`, or a
//! `route::FnTarget` for your own delivery handler.

// Always present: the shared vocabulary and the light glue that builds on it.
pub mod compose;
mod core;
pub mod identity;

// `send` — the outbound engine.
#[cfg(feature = "send")]
pub mod out;

// `server` — accept, spool, deliver. (Implies `send`.)
#[cfg(feature = "server")]
pub mod inbound;
#[cfg(feature = "server")]
pub mod policy;
#[cfg(feature = "server")]
pub mod route;
#[cfg(feature = "server")]
pub mod serve;
#[cfg(feature = "server")]
pub mod spool;
#[cfg(feature = "server")]
pub mod store;
#[cfg(feature = "server")]
pub mod worker;

// `inspect` — probe the world and judge the evidence.
#[cfg(feature = "inspect")]
pub mod checklist;
#[cfg(feature = "inspect")]
pub mod inspect;
#[cfg(feature = "inspect")]
pub mod probe;
#[cfg(feature = "inspect")]
pub mod sheet;

// `cli` — the interactive console behind the binary.
#[cfg(feature = "cli")]
pub mod console;

// `core` stays private; its public vocabulary is surfaced at the crate root.
pub use crate::core::config;
pub use crate::core::{EmailAddress, Envelope, MailEvent, Message};

/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
