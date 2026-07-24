//! # route — where accepted mail goes
//!
//! Once a message is accepted, it flows to one or more **delivery targets**.
//! Native targets (a mailbox store now; forward / webhook / queue later) and
//! a downstream program's own handler implement one trait, so the delivery
//! worker treats them all alike.
//!
//! The [`ChannelTarget`] is the simplest **embedding seam**: a program that
//! embeds mailbourne as a library (say, an automation platform enabling a
//! mail server) just drains received messages from a channel and does
//! whatever it likes with them — no trait to implement.

use async_trait::async_trait;
use mailbourne_in::session::ReceivedMessage;
use mailbourne_store::Maildir;

/// How a delivery attempt ended. `Failed` is retryable by the worker.
#[derive(Debug)]
pub enum DeliveryOutcome {
    /// The message reached this target.
    Delivered,
    /// It didn't — with a reason. The delivery worker should retry.
    Failed(String),
}

/// A destination for accepted mail. Native targets and a downstream app's
/// own handler implement it identically.
#[async_trait]
pub trait DeliveryTarget: Send + Sync {
    /// Deliver one accepted message to this target.
    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome;
}

/// Stores each recipient's copy into a Maildir.
pub struct MailboxTarget {
    store: Maildir,
}

impl MailboxTarget {
    /// Wraps a store as a delivery target.
    pub fn new(store: Maildir) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DeliveryTarget for MailboxTarget {
    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        for rcpt in &message.rcpt_to {
            if let Err(e) = self.store.store(rcpt, &message.data).await {
                return DeliveryOutcome::Failed(e.to_string());
            }
        }
        DeliveryOutcome::Delivered
    }
}

/// Hands each message to an in-process channel — the seam for embedding
/// mailbourne in another Rust program. The embedder drains the receiver.
pub struct ChannelTarget {
    tx: tokio::sync::mpsc::Sender<ReceivedMessage>,
}

impl ChannelTarget {
    /// Creates a channel target and returns the receiver to drain.
    pub fn new(buffer: usize) -> (Self, tokio::sync::mpsc::Receiver<ReceivedMessage>) {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);
        (Self { tx }, rx)
    }
}

#[async_trait]
impl DeliveryTarget for ChannelTarget {
    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        match self.tx.send(message.clone()).await {
            Ok(()) => DeliveryOutcome::Delivered,
            Err(_) => DeliveryOutcome::Failed("the embedding receiver was dropped".to_string()),
        }
    }
}
