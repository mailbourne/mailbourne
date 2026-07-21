//! # dns — asking the address book
//!
//! DNS is the address book of email. These probes ask it the four questions
//! that decide whether mail flows:
//!
//! - [`mx`]: *where does this domain's mail live?* (routing)
//! - [`spf`]: *who is allowed to send for it?* (the guest list)
//! - [`dkim`]: *is the public key published?* (the wax seal's other half)
//! - [`ptr`]: *does the IP's name match its forward DNS?* (caller ID)
//!
//! Implementations arrive with `hickory-resolver` in Milestone 0.

pub mod dkim;
pub mod mx;
pub mod ptr;
pub mod spf;
