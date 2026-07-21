//! # message — the letter inside
//!
//! The message is everything transmitted after SMTP's `DATA` command: the
//! headers (`From:`, `To:`, `Subject:`, `Date:`) and the body, in the format
//! RFC 5322 defines. DKIM signs *this* (or parts of it); the envelope is
//! never signed because it is rewritten at every hop.

/// A raw RFC 5322 message as bytes.
///
/// Held as bytes rather than a parsed structure because DKIM verification
/// is canonicalization-sensitive: the signature covers the *exact* bytes,
/// so re-serializing a parsed form would break it. Parsing (via
/// `mail-parser`) is done on demand, never destructively.
#[derive(Debug, Clone)]
pub struct Message {
    raw: Vec<u8>,
}

impl Message {
    /// Wraps raw RFC 5322 bytes without validating them.
    ///
    /// Validation and construction helpers arrive with the builder
    /// integration (`mail-builder`).
    pub fn from_raw(raw: Vec<u8>) -> Self {
        Self { raw }
    }

    /// The exact bytes of the message — what travels inside `DATA`, and
    /// what DKIM signatures are computed over.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}
