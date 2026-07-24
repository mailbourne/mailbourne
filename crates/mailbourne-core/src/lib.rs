//! # mailbourne-core — the vocabulary
//!
//! Start here. These are the nouns of email that every other crate shares.
//!
//! The single most important idea in this crate — and in all of email — is
//! the difference between the **envelope** and the **message**:
//!
//! - The [`envelope::Envelope`] is what the *servers* read: who to bounce to
//!   (`MAIL FROM`) and where to deliver (`RCPT TO`). Like the outside of a
//!   paper envelope, it is thrown away after delivery.
//! - The [`message::Message`] is the letter inside: the headers your mail
//!   client shows (`From:`, `Subject:`) and the body. The receiving server
//!   has no obligation to make it match the envelope — that mismatch is how
//!   BCC works, and policing it is what SPF/DKIM/DMARC are for.
//!
//! Reading order: [`address`] → [`envelope`] → [`message`] → [`event`] → [`config`].

pub mod address;
pub mod config;
pub mod edit;
pub mod envelope;
pub mod event;
pub mod message;

pub use address::EmailAddress;
pub use envelope::Envelope;
pub use event::MailEvent;
pub use message::Message;
