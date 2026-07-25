//! # worker — the async delivery worker
//!
//! Reads due messages from the durable [`Spool`], delivers each to its
//! **pending** targets, and settles the outcome: fully delivered → gone,
//! some targets still failing → rescheduled with backoff. This is the half
//! that lets a slow or down target (a webhook, a remote MX) retry without
//! ever stalling the SMTP session or losing an accepted message.
//!
//! Retry timing reuses the outbound engine's [`Policy`] — the same
//! backoff-then-give-up schedule that governs sending. Per-target tracking
//! (from the spool) means a message stored but not yet forwarded won't be
//! stored twice on retry.

use crate::send::retry::Policy;
use crate::server::inbound::session::ReceivedMessage;
use crate::server::route::{DeliveryOutcome, DeliveryTarget};
use crate::server::spool::{Spool, SpoolError};
use std::sync::Arc;
use std::time::Duration;

/// How often the worker wakes to check the spool.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Processes every due spool entry once: deliver to each pending target,
/// then settle (remove if fully delivered, else reschedule with backoff).
///
/// # Errors
/// Propagates spool I/O errors. A single unreadable entry is skipped, not
/// fatal.
pub async fn tick(
    spool: &Spool,
    targets: &[Arc<dyn DeliveryTarget>],
    now_unix: u64,
    retry: &Policy,
) -> Result<(), SpoolError> {
    for id in spool.list_due(now_unix).await? {
        let entry = match spool.load(&id).await {
            Ok(entry) => entry,
            Err(_) => continue, // skip an unreadable entry rather than die
        };
        let message = ReceivedMessage {
            mail_from: entry.mail_from.clone(),
            rcpt_to: entry.rcpt_to.clone(),
            data: entry.data.clone(),
        };

        // Try each pending target; keep the ones that still fail.
        let mut still_pending = Vec::new();
        for target_name in &entry.pending {
            match targets.iter().find(|t| t.name() == target_name) {
                Some(target) => {
                    if let DeliveryOutcome::Failed(_) = target.deliver(&message).await {
                        still_pending.push(target_name.clone());
                    }
                }
                // A target that's no longer configured is quietly dropped.
                None => {}
            }
        }

        let attempts = entry.attempts + 1;
        if still_pending.is_empty() {
            spool.settle(&id, &[], attempts, 0).await?; // done → removed
            continue;
        }

        let elapsed = Duration::from_secs(now_unix.saturating_sub(entry.enqueued_unix));
        match retry.next_delay(attempts, elapsed) {
            Some(delay) => {
                spool
                    .settle(&id, &still_pending, attempts, now_unix + delay.as_secs())
                    .await?;
            }
            None => {
                // Retry budget spent. For now we drop it; a proper bounce to
                // the sender arrives with the narrator.
                spool.settle(&id, &[], attempts, 0).await?;
            }
        }
    }
    Ok(())
}

/// Runs the worker forever, ticking every [`POLL_INTERVAL`].
pub async fn run(spool: Spool, targets: crate::server::serve::Targets, retry: Policy) {
    loop {
        let now = now_unix();
        // Errors here are transient (a disk hiccup); the next tick retries.
        let _ = tick(&spool, &targets, now, &retry).await;
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Current time as unix seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::route::FnTarget;

    fn temp() -> std::path::PathBuf {
        // Nanos + a per-process counter so parallel tests never share a dir.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("mb-worker-{nanos}-{seq}"))
    }

    fn ok_target() -> Arc<dyn DeliveryTarget> {
        Arc::new(FnTarget::new("ok", |_msg| async {
            DeliveryOutcome::Delivered
        }))
    }
    fn failing_target() -> Arc<dyn DeliveryTarget> {
        Arc::new(FnTarget::new("fail", |_msg| async {
            DeliveryOutcome::Failed("nope".to_string())
        }))
    }

    #[tokio::test]
    async fn a_tick_delivers_the_good_target_and_reschedules_the_failing_one() {
        let dir = temp();
        let spool = Spool::at(&dir);
        let id = spool
            .enqueue(
                "a@b.com",
                &["x@y.z".into()],
                b"m",
                &["ok".into(), "fail".into()],
                1000,
            )
            .await
            .unwrap();

        tick(
            &spool,
            &[ok_target(), failing_target()],
            1000,
            &Policy::default(),
        )
        .await
        .unwrap();

        // "ok" is done; "fail" remains, rescheduled into the future.
        assert!(spool.list_due(1000).await.unwrap().is_empty());
        let entry = spool.load(&id).await.unwrap();
        assert_eq!(entry.pending, vec!["fail".to_string()]);
        assert_eq!(entry.attempts, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_fully_delivered_message_is_removed_from_the_spool() {
        let dir = temp();
        let spool = Spool::at(&dir);
        let id = spool
            .enqueue("a@b.com", &["x@y.z".into()], b"m", &["ok".into()], 1000)
            .await
            .unwrap();

        tick(&spool, &[ok_target()], 1000, &Policy::default())
            .await
            .unwrap();

        assert!(spool.load(&id).await.is_err(), "delivered → gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failing_target_recovers_on_a_later_tick() {
        // Round 1 fails and reschedules; round 2 (with a now-working target)
        // delivers and clears the spool — the retry loop, proven.
        let dir = temp();
        let spool = Spool::at(&dir);
        let id = spool
            .enqueue("a@b.com", &["x@y.z".into()], b"m", &["flaky".into()], 1000)
            .await
            .unwrap();

        let broken: Arc<dyn DeliveryTarget> = Arc::new(FnTarget::new("flaky", |_m| async {
            DeliveryOutcome::Failed("down".to_string())
        }));
        tick(&spool, &[broken], 1000, &Policy::default())
            .await
            .unwrap();
        assert_eq!(
            spool.load(&id).await.unwrap().pending,
            vec!["flaky".to_string()]
        );

        // Later, past the backoff, with the target working again:
        let fixed: Arc<dyn DeliveryTarget> = Arc::new(FnTarget::new("flaky", |_m| async {
            DeliveryOutcome::Delivered
        }));
        tick(&spool, &[fixed], 9_999_999, &Policy::default())
            .await
            .unwrap();
        assert!(spool.load(&id).await.is_err(), "recovered and cleared");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
