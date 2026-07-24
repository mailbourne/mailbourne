//! # serve — run mailbourne as a receiving server
//!
//! Binds a listener and, for each connection, runs the server-side SMTP
//! session ([`mailbourne_in`]) and delivers accepted messages to the store
//! ([`mailbourne_store`]). This is the daemon face of the engine —
//! `mailbourne serve`, and the docker image's default command.
//!
//! For now it accepts every recipient and stores to Maildir; recipient
//! validation, the policy pipeline, and richer routing arrive with the next
//! milestones.

use mailbourne_store::Maildir;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Binds `addr` and serves forever — one spawned task per connection.
///
/// # Errors
/// Fails if the address can't be bound (e.g. port 25 needs privilege, or is
/// already in use).
pub async fn run(addr: SocketAddr, hostname: String, store: Maildir) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let hostname = hostname.clone();
        let store = store.clone();
        tokio::spawn(async move {
            handle_connection(stream, &hostname, &store).await;
        });
    }
}

/// Handles one connection: run the SMTP session, then deliver each accepted
/// message into each recipient's mailbox.
async fn handle_connection(stream: tokio::net::TcpStream, hostname: &str, store: &Maildir) {
    let messages = match mailbourne_in::session::serve(stream, hostname).await {
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
            handle_connection(stream, "mail.test", &store_for_server).await;
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
