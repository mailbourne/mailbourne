//! # spool — the durable delivery queue
//!
//! Once a message is accepted (`250`), we own it — losing it is the one
//! unforgivable failure. So an accepted message is written **here, to disk,
//! before we answer `250`**, and only then does an async delivery worker
//! route it to its targets, retrying the failures with backoff. A crash
//! after `250` loses nothing: the spool is re-read on restart.
//!
//! Each entry tracks its **pending targets** by name, so a retry re-runs
//! only the ones that haven't succeeded — a message stored but not yet
//! forwarded won't be stored twice.
//!
//! Two files per entry: `<id>.eml` (the raw message bytes) and `<id>.json`
//! (the envelope + delivery state). Storing the body separately keeps it
//! out of JSON (no base64 bloat, binary-safe).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A durable, on-disk delivery queue rooted at a directory.
///
/// A capped spool (see [`Spool::with_cap`]) bounds the waiting room: once the
/// live message bytes reach the cap, [`enqueue`](Spool::enqueue) refuses with
/// [`SpoolError::Full`] rather than let the queue grow until the disk does.
/// The SMTP session turns that refusal into a `451` — the sender holds the
/// mail and retries, so nothing is dropped.
#[derive(Debug, Clone)]
pub struct Spool {
    dir: PathBuf,
    /// Byte budget for message bodies; `0` means unlimited.
    max_bytes: u64,
    /// Live message-body bytes currently spooled (tracked only when capped).
    used: Arc<AtomicU64>,
}

/// One spooled message plus its delivery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The spool id (also the filename stem).
    pub id: String,
    /// Envelope sender (`""` = null sender).
    pub mail_from: String,
    /// Envelope recipients.
    pub rcpt_to: Vec<String>,
    /// The raw message bytes.
    pub data: Vec<u8>,
    /// Target names still to deliver to.
    pub pending: Vec<String>,
    /// How many delivery rounds have been attempted.
    pub attempts: u32,
    /// When the message was first spooled (unix seconds).
    pub enqueued_unix: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Meta {
    mail_from: String,
    rcpt_to: Vec<String>,
    pending: Vec<String>,
    attempts: u32,
    enqueued_unix: u64,
    next_retry_unix: u64,
}

/// Why a spool operation failed.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// A filesystem operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The metadata file was corrupt.
    #[error("corrupt spool metadata: {0}")]
    Corrupt(String),
    /// The spool is at its byte cap — the message was not accepted.
    #[error("spool is full")]
    Full,
}

impl Spool {
    /// Roots an **unlimited** spool at `dir` — no cap, no refusals.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            max_bytes: 0,
            used: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Roots a spool at `dir` bounded to `max_bytes` of live message bodies.
    ///
    /// Existing entries on disk are re-scanned so a restart resumes with an
    /// accurate count (bytes already waiting still count against the cap).
    /// A `max_bytes` of `0` is unlimited, exactly like [`Spool::at`].
    ///
    /// # Errors
    /// Fails if the spool directory can't be read while seeding the count.
    pub async fn with_cap(dir: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, SpoolError> {
        let dir = dir.into();
        let used = if max_bytes == 0 {
            0
        } else {
            scan_used_bytes(&dir).await?
        };
        Ok(Self {
            dir,
            max_bytes,
            used: Arc::new(AtomicU64::new(used)),
        })
    }

    /// Writes a newly-accepted message to disk, due for immediate delivery
    /// to `targets`. Returns the spool id. Call this **before** answering
    /// `250` — that's the durability guarantee.
    ///
    /// # Errors
    /// Fails if the spool directory or entry files can't be written.
    pub async fn enqueue(
        &self,
        mail_from: &str,
        rcpt_to: &[String],
        data: &[u8],
        targets: &[String],
        now_unix: u64,
    ) -> Result<String, SpoolError> {
        // Backpressure: refuse before writing once the room is full. Slight
        // overshoot under concurrent enqueues is fine — it's a soft cap.
        if self.max_bytes > 0
            && self.used.load(Ordering::Acquire) + data.len() as u64 > self.max_bytes
        {
            return Err(SpoolError::Full);
        }
        tokio::fs::create_dir_all(&self.dir).await?;
        let id = unique_id();
        tokio::fs::write(self.dir.join(format!("{id}.eml")), data).await?;
        if self.max_bytes > 0 {
            self.used.fetch_add(data.len() as u64, Ordering::AcqRel);
        }
        let meta = Meta {
            mail_from: mail_from.to_string(),
            rcpt_to: rcpt_to.to_vec(),
            pending: targets.to_vec(),
            attempts: 0,
            enqueued_unix: now_unix,
            next_retry_unix: now_unix, // due immediately
        };
        let json =
            serde_json::to_vec_pretty(&meta).map_err(|e| SpoolError::Corrupt(e.to_string()))?;
        tokio::fs::write(self.dir.join(format!("{id}.json")), json).await?;
        Ok(id)
    }

    /// Ids of entries due for a delivery attempt (next_retry ≤ now).
    ///
    /// # Errors
    /// Fails if the spool can't be read, or an entry's metadata is corrupt.
    pub async fn list_due(&self, now_unix: u64) -> Result<Vec<String>, SpoolError> {
        let mut due = Vec::new();
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(due),
            Err(e) => return Err(e.into()),
        };
        while let Some(dirent) = entries.next_entry().await? {
            let path = dirent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = tokio::fs::read(&path).await?;
            let meta: Meta =
                serde_json::from_slice(&bytes).map_err(|e| SpoolError::Corrupt(e.to_string()))?;
            if meta.next_retry_unix <= now_unix
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                due.push(stem.to_string());
            }
        }
        due.sort();
        Ok(due)
    }

    /// Loads a full entry by id.
    ///
    /// # Errors
    /// Fails if the entry is missing, unreadable, or its metadata is corrupt.
    pub async fn load(&self, id: &str) -> Result<Entry, SpoolError> {
        let bytes = tokio::fs::read(self.dir.join(format!("{id}.json"))).await?;
        let meta: Meta =
            serde_json::from_slice(&bytes).map_err(|e| SpoolError::Corrupt(e.to_string()))?;
        let data = tokio::fs::read(self.dir.join(format!("{id}.eml"))).await?;
        Ok(Entry {
            id: id.to_string(),
            mail_from: meta.mail_from,
            rcpt_to: meta.rcpt_to,
            data,
            pending: meta.pending,
            attempts: meta.attempts,
            enqueued_unix: meta.enqueued_unix,
        })
    }

    /// Records the outcome of a delivery round. If `still_pending` is empty
    /// the entry is **removed** (fully delivered); otherwise its metadata is
    /// rewritten with the remaining targets, a bumped attempt count, and the
    /// next retry time.
    ///
    /// # Errors
    /// Fails if the surviving entry's metadata can't be re-read or rewritten.
    pub async fn settle(
        &self,
        id: &str,
        still_pending: &[String],
        attempts: u32,
        next_retry_unix: u64,
    ) -> Result<(), SpoolError> {
        if still_pending.is_empty() {
            // Fully delivered — drop both files and give the bytes back.
            let eml = self.dir.join(format!("{id}.eml"));
            if self.max_bytes > 0
                && let Ok(meta) = tokio::fs::metadata(&eml).await
            {
                self.used.fetch_sub(meta.len(), Ordering::AcqRel);
            }
            let _ = tokio::fs::remove_file(&eml).await;
            let _ = tokio::fs::remove_file(self.dir.join(format!("{id}.json"))).await;
            return Ok(());
        }
        // Rewrite metadata with the remaining targets and next attempt time.
        let path = self.dir.join(format!("{id}.json"));
        let bytes = tokio::fs::read(&path).await?;
        let mut meta: Meta =
            serde_json::from_slice(&bytes).map_err(|e| SpoolError::Corrupt(e.to_string()))?;
        meta.pending = still_pending.to_vec();
        meta.attempts = attempts;
        meta.next_retry_unix = next_retry_unix;
        let json =
            serde_json::to_vec_pretty(&meta).map_err(|e| SpoolError::Corrupt(e.to_string()))?;
        tokio::fs::write(&path, json).await?;
        Ok(())
    }
}

/// Sums the sizes of every `.eml` body under `dir` — the live byte count a
/// capped spool resumes from. A missing directory is simply zero.
async fn scan_used_bytes(dir: &std::path::Path) -> Result<u64, SpoolError> {
    let mut total = 0u64;
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    while let Some(dirent) = entries.next_entry().await? {
        let path = dirent.path();
        if path.extension().and_then(|e| e.to_str()) == Some("eml") {
            total += dirent.metadata().await?.len();
        }
    }
    Ok(total)
}

fn unique_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{seq}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!("mb-spool-{}", unique_id()))
    }

    // A message whose `.eml` body is exactly `n` bytes, so cap math is exact.
    fn body(n: usize) -> Vec<u8> {
        vec![b'x'; n]
    }

    #[tokio::test]
    async fn enqueue_past_the_cap_is_refused() {
        // The waiting room is bounded: once it's full, a new message is
        // refused with `Full` (which the SMTP session turns into a 451 —
        // backpressure, never a silent drop).
        let dir = temp();
        let spool = Spool::with_cap(&dir, 100).await.unwrap();
        spool
            .enqueue("a@b.com", &["x@y.z".into()], &body(60), &["t".into()], 1)
            .await
            .unwrap();
        let err = spool
            .enqueue("a@b.com", &["x@y.z".into()], &body(60), &["t".into()], 1)
            .await
            .unwrap_err();
        assert!(matches!(err, SpoolError::Full));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn settling_a_delivered_message_frees_capacity() {
        // Delivery drains the room: once a message leaves, its space is
        // reusable — the cap tracks live bytes, not a high-water mark.
        let dir = temp();
        let spool = Spool::with_cap(&dir, 100).await.unwrap();
        let id = spool
            .enqueue("a@b.com", &["x@y.z".into()], &body(60), &["t".into()], 1)
            .await
            .unwrap();
        spool.settle(&id, &[], 1, 0).await.unwrap(); // delivered → removed
        // Now there's room again.
        spool
            .enqueue("a@b.com", &["x@y.z".into()], &body(60), &["t".into()], 1)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_reopened_capped_spool_counts_what_is_already_there() {
        // Restart safety: a capped spool re-scans the disk on open, so bytes
        // already waiting still count against the cap.
        let dir = temp();
        Spool::with_cap(&dir, 1000)
            .await
            .unwrap()
            .enqueue("a@b.com", &["x@y.z".into()], &body(60), &["t".into()], 1)
            .await
            .unwrap();

        let reopened = Spool::with_cap(&dir, 100).await.unwrap();
        let err = reopened
            .enqueue("a@b.com", &["x@y.z".into()], &body(60), &["t".into()], 1)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SpoolError::Full),
            "existing 60 + new 60 > 100"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_uncapped_spool_never_refuses() {
        // `at` is the unlimited waiting room — no cap, no refusals.
        let dir = temp();
        let spool = Spool::at(&dir);
        for _ in 0..5 {
            spool
                .enqueue("a@b.com", &["x@y.z".into()], &body(1_000), &["t".into()], 1)
                .await
                .unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_enqueued_message_survives_a_fresh_spool_handle() {
        // Durability: enqueue, then a NEW Spool at the same dir (a restart)
        // still finds and loads the message intact.
        let dir = temp();
        let id = Spool::at(&dir)
            .enqueue(
                "a@b.com",
                &["bob@us.example".into()],
                b"Subject: hi\r\n\r\nbody",
                &["mailbox".into(), "webhook".into()],
                100,
            )
            .await
            .unwrap();

        let reopened = Spool::at(&dir);
        let due = reopened.list_due(100).await.unwrap();
        assert_eq!(due, vec![id.clone()]);

        let entry = reopened.load(&id).await.unwrap();
        assert_eq!(entry.mail_from, "a@b.com");
        assert_eq!(entry.rcpt_to, vec!["bob@us.example".to_string()]);
        assert_eq!(entry.data, b"Subject: hi\r\n\r\nbody");
        assert_eq!(
            entry.pending,
            vec!["mailbox".to_string(), "webhook".to_string()]
        );
        assert_eq!(entry.attempts, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_due_excludes_entries_not_yet_ready() {
        let dir = temp();
        let spool = Spool::at(&dir);
        let id = spool
            .enqueue("a@b.com", &["x@y.z".into()], b"m", &["mailbox".into()], 100)
            .await
            .unwrap();
        // Push its next retry into the future.
        spool
            .settle(&id, &["mailbox".into()], 1, 500)
            .await
            .unwrap();
        assert!(
            spool.list_due(200).await.unwrap().is_empty(),
            "not due at 200"
        );
        assert_eq!(spool.list_due(500).await.unwrap(), vec![id], "due at 500");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn settling_with_no_pending_removes_the_entry() {
        let dir = temp();
        let spool = Spool::at(&dir);
        let id = spool
            .enqueue("a@b.com", &["x@y.z".into()], b"m", &["mailbox".into()], 100)
            .await
            .unwrap();
        spool.settle(&id, &[], 1, 0).await.unwrap(); // fully delivered
        assert!(spool.list_due(9999).await.unwrap().is_empty());
        assert!(spool.load(&id).await.is_err(), "entry should be gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn settling_with_remaining_targets_keeps_only_those() {
        let dir = temp();
        let spool = Spool::at(&dir);
        let id = spool
            .enqueue(
                "a@b.com",
                &["x@y.z".into()],
                b"m",
                &["mailbox".into(), "webhook".into()],
                100,
            )
            .await
            .unwrap();
        // mailbox delivered, webhook still pending.
        spool
            .settle(&id, &["webhook".into()], 1, 300)
            .await
            .unwrap();
        let entry = spool.load(&id).await.unwrap();
        assert_eq!(entry.pending, vec!["webhook".to_string()]);
        assert_eq!(entry.attempts, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
