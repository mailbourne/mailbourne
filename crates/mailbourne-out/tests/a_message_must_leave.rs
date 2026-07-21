//! The whole outbound journey, end to end, over a real TCP socket:
//! route → dial → conversation → outcome. The only fake is the server on
//! the other end — everything of ours is the production path.

use mailbourne_core::{EmailAddress, Envelope, Message};
use mailbourne_out::conversation::Outcome;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A minimal friendly MX listening on a real local port.
async fn spawn_fake_mx() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut chat = BufReader::new(stream);
                chat.get_mut().write_all(b"220 fake ready\r\n").await.ok();
                let mut line = String::new();
                loop {
                    line.clear();
                    if chat.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let upper = line.to_uppercase();
                    let reply: &[u8] = if upper.starts_with("EHLO") {
                        b"250 fake at your service\r\n"
                    } else if upper.starts_with("MAIL") || upper.starts_with("RCPT") {
                        b"250 ok\r\n"
                    } else if upper.starts_with("DATA") {
                        chat.get_mut().write_all(b"354 go\r\n").await.ok();
                        loop {
                            line.clear();
                            if chat.read_line(&mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            if line == ".\r\n" {
                                break;
                            }
                        }
                        b"250 queued\r\n"
                    } else if upper.starts_with("QUIT") {
                        chat.get_mut().write_all(b"221 bye\r\n").await.ok();
                        return;
                    } else {
                        b"500 what\r\n"
                    };
                    chat.get_mut().write_all(reply).await.ok();
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn a_message_leaves_through_a_real_socket() {
    let addr = spawn_fake_mx().await;

    let envelope = Envelope {
        mail_from: EmailAddress::parse("alice@us.example").unwrap(),
        rcpt_to: vec![EmailAddress::parse("bob@fake.mx").unwrap()],
    };
    let message = Message::from_raw(b"Subject: leaving\r\n\r\ngoodbye!\r\n".to_vec());

    let outcome = mailbourne_out::send_to_host(
        &addr.ip().to_string(),
        addr.port(),
        "mail.us.example",
        &envelope,
        &message,
    )
    .await
    .unwrap();

    assert!(matches!(outcome, Outcome::Delivered { .. }));
}
