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
    /// A stable name for this target (`"mailbox"`, `"forward"`, a custom
    /// label). The delivery worker uses it to track which targets a message
    /// still needs — so a retry re-runs only the ones that failed.
    fn name(&self) -> &str;

    /// Deliver one accepted message to this target.
    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome;
}

/// A delivery target backed by a downstream app's own async Rust function.
///
/// The most direct embedding seam: mailbourne calls your function once per
/// accepted message. A program embedding the engine (say, an automation
/// platform enabling a mail server) writes its handler as a plain async
/// closure — no trait to implement:
///
/// ```no_run
/// # use mailbourne::route::{FnTarget, DeliveryOutcome};
/// let target = FnTarget::new("my-app", |msg| async move {
///     // do anything with msg…
///     DeliveryOutcome::Delivered
/// });
/// ```
pub struct FnTarget<F> {
    name: String,
    handler: F,
}

impl<F, Fut> FnTarget<F>
where
    F: Fn(ReceivedMessage) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = DeliveryOutcome> + Send,
{
    /// Wraps an async closure as a named delivery target.
    pub fn new(name: impl Into<String>, handler: F) -> Self {
        Self {
            name: name.into(),
            handler,
        }
    }
}

#[async_trait]
impl<F, Fut> DeliveryTarget for FnTarget<F>
where
    F: Fn(ReceivedMessage) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = DeliveryOutcome> + Send,
{
    fn name(&self) -> &str {
        &self.name
    }

    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        (self.handler)(message.clone()).await
    }
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
    fn name(&self) -> &str {
        "mailbox"
    }

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
    fn name(&self) -> &str {
        "channel"
    }

    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        match self.tx.send(message.clone()).await {
            Ok(()) => DeliveryOutcome::Delivered,
            Err(_) => DeliveryOutcome::Failed("the embedding receiver was dropped".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailbourne_in::session::ReceivedMessage;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_function_target_runs_the_downstream_closure() {
        // The embedding seam: a downstream app plugs in a plain async Rust
        // function, and mailbourne calls it per accepted message.
        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = seen.clone();
        let target = FnTarget::new("downstream", move |msg: ReceivedMessage| {
            let seen = seen2.clone();
            async move {
                assert_eq!(msg.mail_from, "a@b.com");
                seen.fetch_add(1, Ordering::SeqCst);
                DeliveryOutcome::Delivered
            }
        });

        let msg = ReceivedMessage {
            mail_from: "a@b.com".to_string(),
            rcpt_to: vec!["bob@us.example".to_string()],
            data: b"hi".to_vec(),
        };
        let outcome = target.deliver(&msg).await;
        assert!(matches!(outcome, DeliveryOutcome::Delivered));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        assert_eq!(target.name(), "downstream");
    }
}
