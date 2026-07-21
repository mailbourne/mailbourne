//! # address — who mail is for
//!
//! An email address is two names joined by `@`: the **local part** (which
//! mailbox) and the **domain** (which server's world that mailbox lives in).
//! Everything in routing cares only about the domain; everything in delivery
//! cares only about the local part.

use std::fmt;

/// A parsed email address: `local@domain`.
///
/// # Example
/// ```
/// use mailbourne_core::EmailAddress;
///
/// let addr = EmailAddress::parse("alice@example.com").unwrap();
/// assert_eq!(addr.local(), "alice");
/// assert_eq!(addr.domain(), "example.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress {
    local: String,
    domain: String,
}

/// Why an address string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// No `@` found, or more than one outside a quoted local part.
    MissingAt,
    /// The part before `@` is empty.
    EmptyLocal,
    /// The part after `@` is empty.
    EmptyDomain,
}

impl EmailAddress {
    /// Parses `local@domain` from a string.
    ///
    /// This is deliberately strict-and-simple for now: one `@`, non-empty
    /// halves. Full RFC 5321 address grammar (quoted locals, literals)
    /// arrives with the parser integration.
    ///
    /// # Errors
    /// Returns an [`AddressError`] describing which structural rule failed.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let (local, domain) = s.rsplit_once('@').ok_or(AddressError::MissingAt)?;
        if local.is_empty() {
            return Err(AddressError::EmptyLocal);
        }
        if domain.is_empty() {
            return Err(AddressError::EmptyDomain);
        }
        Ok(Self {
            local: local.to_string(),
            domain: domain.to_string(),
        })
    }

    /// The mailbox name — the part before `@`.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The domain — the part after `@`, and the only part routing looks at.
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}
