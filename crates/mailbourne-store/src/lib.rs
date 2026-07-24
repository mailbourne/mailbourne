//! # mailbourne-store — where received mail rests
//!
//! The first delivery target: a **Maildir** on disk — the format
//! Postfix/Dovecot use. One file per message, written into `tmp/` and then
//! atomically renamed into `new/`, so a reader never sees a half-written
//! message. (The `DeliveryTarget` trait and the other targets — window
//! store, forward, webhook, queue — arrive with the routing milestone.)
//!
//! Defense (POLICY.md): the mailbox name is derived from an
//! attacker-controlled recipient address, so it is strictly validated — a
//! recipient can never shape a path that escapes the store root.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A Maildir-backed message store rooted at a directory.
#[derive(Debug, Clone)]
pub struct Maildir {
    root: PathBuf,
}

/// Why a message could not be stored.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The mailbox name (from the recipient) failed validation — it could
    /// have escaped the store root, so we refused it.
    #[error("unsafe mailbox name: {0:?}")]
    UnsafeMailbox(String),
    /// The filesystem operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Maildir {
    /// Roots a store at `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Stores `raw` for `mailbox`, returning the stored filename.
    ///
    /// The mailbox name is validated first (see [`safe_mailbox`]); an
    /// unsafe name is refused before any path is touched.
    ///
    /// # Errors
    /// [`StoreError::UnsafeMailbox`] for a name that isn't safe,
    /// [`StoreError::Io`] for filesystem failures.
    pub async fn store(&self, mailbox: &str, raw: &[u8]) -> Result<String, StoreError> {
        let safe =
            safe_mailbox(mailbox).ok_or_else(|| StoreError::UnsafeMailbox(mailbox.to_string()))?;
        let dir = self.root.join(&safe);
        for sub in ["tmp", "new", "cur"] {
            tokio::fs::create_dir_all(dir.join(sub)).await?;
        }
        let name = unique_name();
        let tmp = dir.join("tmp").join(&name);
        let new = dir.join("new").join(&name);
        // Write to tmp, then atomically rename into new — a reader in new/
        // never sees a partial message.
        tokio::fs::write(&tmp, raw).await?;
        tokio::fs::rename(&tmp, &new).await?;
        Ok(name)
    }
}

/// Validates a mailbox name derived from a recipient address. Allows only
/// `[A-Za-z0-9._@+-]`, forbids `..`, bounds the length — so it can never be
/// a path separator, a traversal, or an absolute path. Returns the safe
/// name, or `None` to refuse.
pub fn safe_mailbox(mailbox: &str) -> Option<String> {
    if mailbox.is_empty() || mailbox.len() > 255 {
        return None;
    }
    if mailbox.contains("..") {
        return None;
    }
    let ok = mailbox
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-'));
    ok.then(|| mailbox.to_string())
}

fn unique_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{nanos}.{pid}_{seq}.mailbourne")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mb-store-{tag}-{}", unique_name()));
        dir
    }

    #[tokio::test]
    async fn a_message_lands_in_new_with_its_bytes() {
        let root = temp_root("basic");
        let store = Maildir::at(&root);
        let name = store
            .store("bob@example.com", b"Subject: hi\r\n\r\nhello\r\n")
            .await
            .unwrap();
        let path = root.join("bob@example.com").join("new").join(&name);
        let got = std::fs::read(&path).unwrap();
        assert_eq!(got, b"Subject: hi\r\n\r\nhello\r\n");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_traversal_recipient_cannot_escape_the_root() {
        let root = temp_root("evil");
        let store = Maildir::at(&root);
        // Classic path-traversal attempt via the recipient address.
        let err = store
            .store("../../../../tmp/evil", b"pwned")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsafeMailbox(_)));
        // And nothing was written anywhere near /tmp/evil.
        assert!(!std::path::Path::new("/tmp/evil").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_mailbox_allows_addresses_and_refuses_tricks() {
        assert!(safe_mailbox("bob@example.com").is_some());
        assert!(safe_mailbox("a.b+tag@x.io").is_some());
        assert!(safe_mailbox("../etc/passwd").is_none());
        assert!(safe_mailbox("a/b").is_none());
        assert!(safe_mailbox("").is_none());
        assert!(safe_mailbox("has space").is_none());
    }

    #[tokio::test]
    async fn two_messages_get_distinct_names() {
        let root = temp_root("distinct");
        let store = Maildir::at(&root);
        let a = store.store("bob@x.io", b"one").await.unwrap();
        let b = store.store("bob@x.io", b"two").await.unwrap();
        assert_ne!(a, b);
        let _ = std::fs::remove_dir_all(&root);
    }
}
