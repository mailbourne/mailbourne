//! # serve — run mailbourne as a receiving server
//!
//! Binds a listener and, for each connection, runs the server-side SMTP
//! session ([`mailbourne_in`]) and delivers accepted messages to the store
//! ([`mailbourne_store`]). This is the daemon face of the engine —
//! `mailbourne serve`, and the docker image's default command.
//!
//! Recipients are validated by the [`mailbourne_policy`] layer — only mail
//! for domains we host is accepted (never an open relay). The wider policy
//! pipeline (SPF/DKIM/DMARC, rate-limit, greylist) and richer routing (spool
//! + delivery worker → store / forward / webhook / queue) arrive next.

use crate::route::DeliveryTarget;
use mailbourne_policy::Policy;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Every accepted message goes to each of these, in order.
pub type Targets = Arc<Vec<Arc<dyn DeliveryTarget>>>;

/// Binds `addr` and serves forever — one spawned task per connection.
///
/// `policy` decides which recipients to accept (never an open relay);
/// `targets` are where accepted mail is routed (a mailbox store, a channel
/// into an embedding app, and — later — forward / webhook / queue).
///
/// # Errors
/// Fails if the address can't be bound (e.g. port 25 needs privilege, or is
/// already in use).
pub async fn run(
    addr: SocketAddr,
    hostname: String,
    policy: Arc<dyn Policy>,
    targets: Targets,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let hostname = hostname.clone();
        let policy = policy.clone();
        let targets = targets.clone();
        tokio::spawn(async move {
            handle_connection(stream, &hostname, policy.as_ref(), &targets).await;
        });
    }
}

/// Handles one connection: run the SMTP session, then route each accepted
/// message to every target.
///
/// (For now this is synchronous — accept then deliver. The durable
/// spool + async delivery worker, which lets a slow or failing target retry
/// without stalling or losing mail, is the next step.)
async fn handle_connection(
    stream: tokio::net::TcpStream,
    hostname: &str,
    policy: &dyn Policy,
    targets: &[Arc<dyn DeliveryTarget>],
) {
    let messages = match mailbourne_in::session::serve(stream, hostname, policy).await {
        Ok(messages) => messages,
        Err(_) => return,
    };
    for message in messages {
        for target in targets {
            // A failure at one target shouldn't lose the others; real error
            // surfacing and retry come with the delivery worker.
            let _ = target.deliver(&message).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::conversation::Outcome;
    use crate::route::{ChannelTarget, MailboxTarget};
    use mailbourne_core::{EmailAddress, Envelope, Message};
    use mailbourne_store::Maildir;

    /// Sends one message from our outbound engine to a one-shot listener
    /// wired with `targets`, and returns after it's handled.
    async fn deliver_to_targets(targets: Vec<Arc<dyn DeliveryTarget>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let policy = mailbourne_policy::HostedDomains::new(["mail.test".to_string()]);
            handle_connection(stream, "mail.test", &policy, &targets).await;
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
