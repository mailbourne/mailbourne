//! # event — everything the engine announces
//!
//! One enum, designed once, used everywhere: the in-process stream that
//! library consumers subscribe to, the log narrator's input, outbound
//! webhooks, and (later) zebflow triggers. If something happens to a
//! message, it is a [`MailEvent`] — there is no second announcement channel.

/// A lifecycle event emitted by the engine.
///
/// Marked `#[non_exhaustive]`: new variants will appear as the engine grows,
/// and consumers must keep a catch-all arm.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum MailEvent {
    /// An outbound message was accepted by the remote server (`250` to our
    /// `DATA`). Responsibility has transferred.
    Delivered {
        /// Engine-assigned identifier of the message.
        message_id: String,
        /// The recipient this delivery was for.
        recipient: String,
    },
    /// The remote server said "not now" (4xx). The message stays queued and
    /// will be retried with backoff — this is normal email behavior, not an
    /// error (greylisting relies on it).
    Deferred {
        /// Engine-assigned identifier of the message.
        message_id: String,
        /// The recipient whose delivery was deferred.
        recipient: String,
        /// Which delivery attempt this was (1-based).
        attempt: u32,
    },
    /// The remote server said "no, permanently" (5xx), or the queue lifetime
    /// expired. A bounce is generated toward the envelope `MAIL FROM`.
    Bounced {
        /// Engine-assigned identifier of the message.
        message_id: String,
        /// The recipient that could not be reached.
        recipient: String,
        /// The SMTP status code that ended the attempt.
        code: u16,
        /// The remote server's human-readable reason line.
        reason: String,
    },
    /// An inbound message was accepted and stored.
    Received {
        /// Engine-assigned identifier of the message.
        message_id: String,
        /// The envelope sender it arrived with.
        from: String,
        /// The local mailbox it was delivered to.
        mailbox: String,
    },
}
