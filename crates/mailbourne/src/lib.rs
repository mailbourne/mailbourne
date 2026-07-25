//! # mailbourne — a liveable mail server and library
//!
//! A liveable mail server and library — a single crate, a single binary,
//! with a built-in inspector for DNS, DKIM, and deliverability.
//!
//! `mailbourne` is one published crate: the binary for operators, and the
//! embeddable library for applications that want to send or receive mail.
//! What used to be a workspace of `mailbourne-*` packages now lives here as
//! modules — read them in dependency order:
//!
//! - `core` — the shared vocabulary: addresses, envelopes, messages, config
//! - `dkim` — mint a signing keypair, derive its publishable record
//! - `probe` / `checklist` / `inspect` — the built-in inspector: gather live
//!   DNS/DKIM evidence and judge it
//! - `out` — the outbound path: DKIM-sign, route by MX, dial, speak
//! - `inbound` — the server side of SMTP (receiving)
//! - `policy` — who we accept mail for (never an open relay)
//! - `store` — where received mail lands (Maildir)
//! - `spool` — the durable queue: accepted before `250`, delivered by a worker
//! - `route`, `serve`, `worker` — glue: targets, the daemon, delivery
//!
//! ## Compose what you embed
//!
//! The inspector, the vocabulary, and DKIM key management are always there.
//! Everything else is a feature — pull only the capability you need, and the
//! rest (and its dependencies) never compiles:
//!
//! ```toml
//! # Just send mail:
//! mailbourne = { version = "0.0.4", default-features = false, features = ["send"] }
//! # Run a receiving server (implies `send`):
//! mailbourne = { version = "0.0.4", default-features = false, features = ["server"] }
//! ```
//!
//! Features: `send` (outbound engine) · `server` (receive + spool + deliver,
//! implies `send`) · `cli` (the operator binary + console; the default).
//! Reach for what you need — `mailbourne::out::send`,
//! `mailbourne::serve::run`, or a `route::FnTarget` for your own handler.

// Always present: the shared vocabulary, DKIM key management, and the
// built-in inspector — probe the world, judge the evidence. The inspector is
// part of what mailbourne *is*, not an optional add-on.
pub mod checklist;
pub mod compose;
mod core;
pub mod dkim;
pub mod identity;
pub mod inspect;
pub mod probe;
pub mod sheet;

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

// `cli` — the interactive console behind the binary.
#[cfg(feature = "cli")]
pub mod console;

// `core` stays private; its public vocabulary is surfaced at the crate root.
pub use crate::core::config;
pub use crate::core::{EmailAddress, Envelope, MailEvent, Message};

/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
