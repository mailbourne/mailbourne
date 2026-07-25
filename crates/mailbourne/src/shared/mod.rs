//! # shared — the reusable foundation
//!
//! What every other group builds on, always compiled. No feature gates it,
//! nothing here depends on `send`/`server`/`cli` — it only ever gets
//! imported, never imports upward.
//!
//! - [`core`] — the vocabulary: addresses, envelopes, messages, events, config
//! - [`dkim`] — mint a signing keypair, derive its publishable record
//! - [`compose`] — build a well-formed [`Message`](core::Message)
//! - [`identity`] — resolve a domain's signing identity from config
//! - [`glossary`] — plain-English descriptions for the jargon (SMTP, DKIM, …)

pub mod compose;
pub mod core;
pub mod dkim;
pub mod glossary;
pub mod identity;
