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
//! - [`core`] — the shared vocabulary: addresses, envelopes, messages, config
//! - [`out`] — the outbound path: compose, DKIM-sign, route by MX, dial, speak
//! - [`inbound`] — the server side of SMTP (receiving)
//! - [`policy`] — who we accept mail for (never an open relay)
//! - [`store`] — where received mail lands (Maildir)
//! - [`spool`] — the durable queue: accepted before `250`, delivered by a worker
//! - [`probe`] / [`checklist`] — gather live DNS evidence and judge it
//! - [`route`], [`serve`], [`worker`] — glue: targets, the daemon, delivery
//!
//! Embedding: depend on `mailbourne` and reach for what you need
//! (`mailbourne::out::send`, `mailbourne::serve::run`, a
//! [`route::FnTarget`] for your own delivery handler).

// Glue: the delivery seam, the daemon, the async worker, and the console.
pub mod compose;
pub mod console;
pub mod identity;
pub mod inspect;
pub mod route;
pub mod serve;
pub mod sheet;
pub mod worker;

// The former `mailbourne-*` crates, now first-class modules of the one crate.
pub mod checklist;
mod core;
pub mod inbound;
pub mod out;
pub mod policy;
pub mod probe;
pub mod spool;
pub mod store;

// `core` stays private; its public vocabulary is surfaced at the crate root.
pub use crate::core::config;
pub use crate::core::{EmailAddress, Envelope, MailEvent, Message};

/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
