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

use mailbourne_policy::Policy;
use mailbourne_store::Maildir;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Binds `addr` and serves forever — one spawned task per connection.
///
/// `policy` decides which recipients to accept (never an open relay);
/// `store` is where accepted mail lands.
///
/// # Errors
/// Fails if the address can't be bound (e.g. port 25 needs privilege, or is
/// already in use).
pub async fn run(
    addr: SocketAddr,
    hostname: String,
    policy: Arc<dyn Policy>,
    store: Maildir,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let hostname = hostname.clone();
        let policy = policy.clone();
        let store = store.clone();
        tokio::spawn(async move {
            handle_connection(stream, &hostname, policy.as_ref(), &store).await;
        });
    }
}

/// Handles one connection: run the SMTP session, then deliver each accepted
/// message into each recipient's mailbox.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    hostname: &str,
    policy: &dyn Policy,
    store: &Maildir,
) {
    let messages = match mailbourne_in::session::serve(stream, hostname, policy).await {
        Ok(messages) => messages,
        Err(_) => return,
    };
    for msg in messages {
        for rcpt in &msg.rcpt_to {
            // A store failure for one recipient shouldn't lose the others;
            // real error surfacing comes with the log narrator.
            let _ = store.store(rcpt, &msg.data).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::conversation::Outcome;
    use mailbourne_core::{EmailAddress, Envelope, Message};

    #[tokio::test]
    async fn a_message_sent_to_our_listener_is_stored() {
        // The whole loop, our own halves talking to each other: our
        // OUTBOUND engine sends to our INBOUND listener, which stores it.
        let root = std::env::temp_dir().join(format!(
            "mb-serve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Maildir::at(&root);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let store_for_server = store.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let policy = mailbourne_policy::HostedDomains::new(["mail.test".to_string()]);
            handle_connection(stream, "mail.test", &policy, &store_for_server).await;
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

        let new_dir = root.join("bob@mail.test").join("new");
        let files: Vec<_> = std::fs::read_dir(&new_dir).unwrap().flatten().collect();
        assert_eq!(files.len(), 1, "exactly one message should be stored");
        let content = std::fs::read_to_string(files[0].path()).unwrap();
        assert!(
            content.contains("hi from the future"),
            "body should be intact"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
