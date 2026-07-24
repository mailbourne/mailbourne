//! # serve — run mailbourne as a receiving server
//!
//! Binds a listener and, for each connection, runs the server-side SMTP
//! session ([`mailbourne_in`]). An accepted message is written to the durable
//! [`Spool`] **before** the session answers `250` — so a crash after `250`
//! loses nothing — and a background [`worker`](crate::worker) drains the spool
//! to the delivery targets, retrying failures with backoff. This is the daemon
//! face of the engine — `mailbourne serve`, and the docker image's default
//! command.
//!
//! Recipients are validated by the [`mailbourne_policy`] layer — only mail
//! for domains we host is accepted (never an open relay). The wider policy
//! pipeline (SPF/DKIM/DMARC, rate-limit, greylist) arrives next.

use crate::route::DeliveryTarget;
use async_trait::async_trait;
use mailbourne_in::session::{Commit, ReceivedMessage};
use mailbourne_out::retry::Policy as RetryPolicy;
use mailbourne_policy::Policy;
use mailbourne_spool::Spool;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Every accepted message is spooled for each of these, by name.
pub type Targets = Arc<Vec<Arc<dyn DeliveryTarget>>>;

/// The durable seam between accepting a message and delivering it: the SMTP
/// session commits each message to the spool (recording which targets it's
/// due for) before answering `250`. Delivery itself is the worker's job.
struct SpoolCommit {
    spool: Spool,
    target_names: Vec<String>,
}

#[async_trait]
impl Commit for SpoolCommit {
    async fn commit(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.spool
            .enqueue(
                &message.mail_from,
                &message.rcpt_to,
                &message.data,
                &self.target_names,
                crate::worker::now_unix(),
            )
            .await
            .map(|_id| ())
            .map_err(|e| e.to_string())
    }
}

/// Binds `addr` and serves forever — one spawned task per connection — while
/// a background worker delivers spooled mail to `targets`.
///
/// `policy` decides which recipients to accept (never an open relay);
/// `targets` are where accepted mail is routed (a mailbox store, a channel or
/// function into an embedding app, and — later — forward / webhook / queue);
/// `spool_dir` is where accepted-but-not-yet-delivered mail lives on disk.
///
/// # Errors
/// Fails if the address can't be bound (e.g. port 25 needs privilege, or is
/// already in use).
pub async fn run(
    addr: SocketAddr,
    hostname: String,
    policy: Arc<dyn Policy>,
    targets: Targets,
    spool_dir: PathBuf,
) -> std::io::Result<()> {
    let spool = Spool::at(spool_dir);
    let target_names: Vec<String> = targets.iter().map(|t| t.name().to_string()).collect();

    // The delivery worker runs alongside the acceptor: it drains the spool to
    // the targets and reschedules failures. Bind first so a bind error is
    // reported before we spawn anything.
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(crate::worker::run(
        spool.clone(),
        targets.clone(),
        RetryPolicy::default(),
    ));

    loop {
        let (stream, _peer) = listener.accept().await?;
        let hostname = hostname.clone();
        let policy = policy.clone();
        let commit = SpoolCommit {
            spool: spool.clone(),
            target_names: target_names.clone(),
        };
        tokio::spawn(async move {
            handle_connection(stream, &hostname, policy.as_ref(), &commit).await;
        });
    }
}

/// Handles one connection: run the SMTP session, committing each accepted
/// message to the spool (via `commit`) before the `250`. Delivery is the
/// worker's job, not this task's.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    hostname: &str,
    policy: &dyn Policy,
    commit: &dyn Commit,
) {
    let _ = mailbourne_in::session::serve(stream, hostname, policy, commit).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::conversation::Outcome;
    use crate::route::{ChannelTarget, MailboxTarget};
    use mailbourne_core::{EmailAddress, Envelope, Message};
    use mailbourne_store::Maildir;

    /// Sends one message from our outbound engine to a one-shot listener,
    /// which commits it to a fresh spool; then ticks the worker once so the
    /// message reaches `targets`. Proves the whole accept → spool → deliver
    /// path, not just an in-memory hop.
    async fn deliver_to_targets(targets: Vec<Arc<dyn DeliveryTarget>>) {
        let spool_dir = std::env::temp_dir().join(format!(
            "mb-serve-spool-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let spool = Spool::at(&spool_dir);
        let commit = SpoolCommit {
            spool: spool.clone(),
            target_names: targets.iter().map(|t| t.name().to_string()).collect(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let policy = mailbourne_policy::HostedDomains::new(["mail.test".to_string()]);
            handle_connection(stream, "mail.test", &policy, &commit).await;
        });

        let envelope = Envelope {
            mail_from: EmailAddress::parse("alice@sender.test").unwrap(),
            rcpt_to: vec![EmailAddress::parse("bob@mail.test").unwrap()],
        };
        let message =
            Message::from_raw(b"Subject: loopback\r\n\r\nhi from the future\r\n".to_vec());
        let outcome = crate::out::send_to_host(
            &addr.ip().to_string(),
            addr.port(),
            "mail.sender.test",
            &envelope,
            &message,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Outcome::Delivered { .. }));
        server.await.unwrap();

        // The session has spooled the message; now the worker delivers it.
        crate::worker::tick(
            &spool,
            &targets,
            crate::worker::now_unix(),
            &RetryPolicy::default(),
        )
        .await
        .unwrap();
        let _ = std::fs::remove_dir_all(&spool_dir);
    }

    #[tokio::test]
    async fn a_message_routes_to_the_mailbox_target() {
        // Our OUTBOUND engine sends to our INBOUND listener, which routes to
        // a Maildir target — both halves of mailbourne, proven end to end.
        let root = std::env::temp_dir().join(format!(
            "mb-serve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Maildir::at(&root);
        deliver_to_targets(vec![Arc::new(MailboxTarget::new(store))]).await;

        let new_dir = root.join("bob@mail.test").join("new");
        let files: Vec<_> = std::fs::read_dir(&new_dir).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
        let content = std::fs::read_to_string(files[0].path()).unwrap();
        assert!(content.contains("hi from the future"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_message_routes_to_an_embedding_channel() {
        // The embedding seam: a downstream app (zebflow-style) receives the
        // message on a channel and can do whatever it likes with it.
        let (target, mut rx) = ChannelTarget::new(8);
        deliver_to_targets(vec![Arc::new(target)]).await;

        let received = rx
            .recv()
            .await
            .expect("a message should arrive on the channel");
        assert_eq!(received.rcpt_to, vec!["bob@mail.test".to_string()]);
        assert!(String::from_utf8_lossy(&received.data).contains("hi from the future"));
    }
}
