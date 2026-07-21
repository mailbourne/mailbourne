//! # envelope — what the servers read
//!
//! During an SMTP conversation, the sender announces `MAIL FROM:<…>` (where
//! bounces go) and `RCPT TO:<…>` (where to deliver). That pair is the
//! **envelope**. It is *not* the `From:`/`To:` your mail client shows — those
//! live inside the [message](crate::message) and may legitimately differ
//! (that difference is how BCC and mailing lists work).

use crate::address::EmailAddress;

/// The SMTP envelope: return path plus recipients.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Where failure notices (bounces) should be sent — the `MAIL FROM`.
    /// SPF is checked against *this* domain, not the visible `From:` header.
    pub mail_from: EmailAddress,
    /// Where the message is actually delivered — the `RCPT TO` list.
    pub rcpt_to: Vec<EmailAddress>,
}
