//! # server — receive, spool, deliver
//!
//! The receiving half of the engine (feature `server`, which implies `send`
//! — a real server also relays and bounces). A connection is accepted by the
//! SMTP session, each message is committed to the durable spool *before* the
//! `250`, and a background worker delivers it to the configured targets,
//! retrying failures with backoff.
//!
//! - [`inbound`] — the server side of SMTP (greet, accept, collect, commit)
//! - [`policy`] — who we accept mail for (never an open relay)
//! - [`store`] — where received mail lands (Maildir)
//! - [`spool`] — the durable queue that makes a `250` a promise
//! - [`route`] — delivery targets (mailbox, channel, `FnTarget`, …)
//! - [`serve`] — bind and serve; the daemon face
//! - [`worker`] — the async delivery worker

pub mod accounts;
pub mod acme;
pub mod door;
pub mod forward;
pub mod inbound;
pub mod outbound;
pub mod policy;
pub mod route;
pub mod serve;
pub mod spool;
pub mod store;
pub mod tls;
pub mod webhook;
pub mod worker;
