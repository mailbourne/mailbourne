//! # session — speak SMTP as the server
//!
//! The receiving mirror of the outbound `deliver`: greet the client, walk
//! it through EHLO → MAIL → RCPT → DATA in strict order, collect the
//! dot-terminated payload, and yield each accepted message. A connection
//! may carry several messages before `QUIT`.
//!
//! Defense posture (POLICY.md — the parser is the perimeter): commands and
//! payload lines are read as bytes (never assumed valid UTF-8), lines and
//! messages are size-capped, out-of-order commands earn a `503`, and DATA
//! ends **only** on an exact `\r\n.\r\n` — bare-LF ambiguity never
//! terminates, which is the SMTP-smuggling defense.

use crate::server::inbound::command::{self, SmtpCommand};
use crate::server::policy::{Policy, Verdict};
use async_trait::async_trait;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// The most a single command or payload line may be before we refuse it.
const MAX_LINE: usize = 8_192;
/// The most a single message body may be.
const MAX_MESSAGE: usize = 50 * 1024 * 1024;
/// The most recipients one transaction may name (spam-amplification cap).
const MAX_RCPT: usize = 100;

/// A message accepted over an SMTP session.
///
/// The envelope is kept as raw strings, not parsed addresses: a receiving
/// server must faithfully hold whatever the client sent — including the
/// empty null sender (`MAIL FROM:<>`) that bounce messages use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// The envelope sender (`""` for the null sender).
    pub mail_from: String,
    /// The envelope recipients.
    pub rcpt_to: Vec<String>,
    /// The raw message bytes (headers + body), dot-unstuffed.
    pub data: Vec<u8>,
}

/// Why a commit was refused, and what to tell the sender.
///
/// Carries the SMTP reply code so the door can answer precisely — `451` when
/// the spool is temporarily full, `452` when a recipient's mailbox is full —
/// rather than one blunt failure code for everything.
#[derive(Debug)]
pub struct CommitReject {
    /// The SMTP reply code (a `4xx` — the sender should retry later).
    pub code: u16,
    /// The human-readable reason, sent alongside the code.
    pub message: String,
}

impl CommitReject {
    /// A rejection with an explicit code and reason.
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// A durable sink for an accepted message.
///
/// The session calls [`commit`](Commit::commit) at the moment a message's
/// DATA ends — **before** it answers `250`. Returning `Ok` means the message
/// is safely persisted (the caller may now be told it's accepted); returning
/// `Err` makes the session answer with the rejection's code instead, so the
/// sender retries rather than believe we took mail we then dropped. This is
/// mailbourne's never-lose-accepted-mail contract, enforced at the wire.
#[async_trait]
pub trait Commit: Send + Sync {
    /// Durably record one accepted message. `Ok` → the session answers
    /// `250`; `Err(reject)` → it answers `reject.code` (a `4xx`).
    async fn commit(&self, message: &ReceivedMessage) -> Result<(), CommitReject>;
}

/// Runs one SMTP session as the server, returning every message accepted
/// before the connection ended.
///
/// Each message is handed to `commit` before the `250` reply — a failed
/// commit yields `451`, never a false acceptance. The returned `Vec` is a
/// convenience for in-process callers and tests; durability rides on
/// `commit`, not on the return value.
///
/// # Errors
/// Propagates socket errors, and treats a connection that drops mid-`DATA`
/// as an [`std::io::ErrorKind::UnexpectedEof`].
pub async fn serve<S>(
    stream: S,
    our_hostname: &str,
    policy: &dyn Policy,
    commit: &dyn Commit,
) -> std::io::Result<Vec<ReceivedMessage>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut messages = Vec::new();

    reply(&mut write, 220, &format!("{our_hostname} ESMTP mailbourne")).await?;

    let mut greeted = false;
    let mut mail_from: Option<String> = None;
    let mut rcpts: Vec<String> = Vec::new();

    loop {
        let line = match read_line(&mut reader).await? {
            Line::Ended => break, // client vanished
            Line::TooLong => {
                reply(&mut write, 500, "line too long").await?;
                break; // fail closed
            }
            Line::Ok(line) => line,
        };

        match command::parse(&line) {
            SmtpCommand::Ehlo(_) | SmtpCommand::Helo(_) => {
                greeted = true;
                mail_from = None;
                rcpts.clear();
                write
                    .write_all(format!("250-{our_hostname} at your service\r\n").as_bytes())
                    .await?;
                write
                    .write_all(format!("250-SIZE {MAX_MESSAGE}\r\n").as_bytes())
                    .await?;
                write.write_all(b"250 8BITMIME\r\n").await?;
                write.flush().await?;
            }
            SmtpCommand::MailFrom(addr) => {
                if !greeted {
                    reply(&mut write, 503, "say EHLO first").await?;
                    continue;
                }
                mail_from = Some(addr);
                rcpts.clear();
                reply(&mut write, 250, "sender ok").await?;
            }
            SmtpCommand::RcptTo(addr) => {
                if mail_from.is_none() {
                    reply(&mut write, 503, "need MAIL FROM first").await?;
                    continue;
                }
                if rcpts.len() >= MAX_RCPT {
                    reply(&mut write, 452, "too many recipients").await?;
                    continue;
                }
                // Acceptance decision: only mail we host (never an open relay).
                match policy.accept_recipient(&addr) {
                    Verdict::Accept => {
                        rcpts.push(addr);
                        reply(&mut write, 250, "recipient ok").await?;
                    }
                    Verdict::Reject(code, msg) => {
                        reply(&mut write, code, &msg).await?;
                    }
                }
            }
            SmtpCommand::Data => {
                if rcpts.is_empty() {
                    reply(&mut write, 503, "need a recipient first").await?;
                    continue;
                }
                reply(&mut write, 354, "go ahead; end with <CRLF>.<CRLF>").await?;
                match read_payload(&mut reader).await? {
                    Some(data) => {
                        let message = ReceivedMessage {
                            mail_from: mail_from.take().unwrap_or_default(),
                            rcpt_to: std::mem::take(&mut rcpts),
                            data,
                        };
                        // Durably record BEFORE promising acceptance. If the
                        // sink can't take it, we answer its code (try again) —
                        // never a 250 for mail we didn't persist.
                        match commit.commit(&message).await {
                            Ok(()) => {
                                messages.push(message);
                                reply(&mut write, 250, "message accepted for delivery").await?;
                            }
                            Err(reject) => {
                                reply(&mut write, reject.code, &reject.message).await?;
                            }
                        }
                    }
                    None => {
                        mail_from = None;
                        rcpts.clear();
                        reply(&mut write, 552, "message exceeds the size limit").await?;
                    }
                }
            }
            SmtpCommand::Rset => {
                mail_from = None;
                rcpts.clear();
                reply(&mut write, 250, "reset").await?;
            }
            SmtpCommand::Noop => reply(&mut write, 250, "ok").await?,
            SmtpCommand::StartTls => reply(&mut write, 502, "STARTTLS not available yet").await?,
            SmtpCommand::Quit => {
                reply(&mut write, 221, "goodbye").await?;
                break;
            }
            SmtpCommand::Unknown(_) => reply(&mut write, 500, "command not recognised").await?,
        }
    }
    Ok(messages)
}

/// The result of reading one command line.
enum Line {
    Ok(String),
    /// Exceeded [`MAX_LINE`] — a defense against unbounded lines.
    TooLong,
    /// The connection closed.
    Ended,
}

/// Reads one command line, bytes-first (never assumes valid UTF-8), trims
/// the CRLF, and caps the length.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Line> {
    let mut raw = Vec::new();
    let n = reader.read_until(b'\n', &mut raw).await?;
    if n == 0 {
        return Ok(Line::Ended);
    }
    if raw.len() > MAX_LINE {
        return Ok(Line::TooLong);
    }
    while matches!(raw.last(), Some(b'\r') | Some(b'\n')) {
        raw.pop();
    }
    Ok(Line::Ok(String::from_utf8_lossy(&raw).into_owned()))
}

/// Collects the DATA payload until the exact terminator `\r\n.\r\n`,
/// reversing dot-stuffing. Returns `None` if the message exceeds
/// [`MAX_MESSAGE`] (the stream is then drained to the terminator so the
/// session stays in sync). A drop mid-DATA is an `UnexpectedEof` error.
async fn read_payload<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut over = false;
    loop {
        let mut raw = Vec::new();
        let n = reader.read_until(b'\n', &mut raw).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed during DATA",
            ));
        }
        // Strict: only an exact ".\r\n" terminates — bare-LF never does.
        if raw == b".\r\n" {
            break;
        }
        if over {
            continue; // draining oversize message to the terminator
        }
        // Un-dot-stuff: a leading '.' was added by the sender; drop one.
        let content: &[u8] = if raw.first() == Some(&b'.') {
            &raw[1..]
        } else {
            &raw[..]
        };
        out.extend_from_slice(content);
        if out.len() > MAX_MESSAGE {
            over = true;
        }
    }
    Ok(if over { None } else { Some(out) })
}

/// Writes a single-line reply.
async fn reply<W: AsyncWrite + Unpin>(write: &mut W, code: u16, text: &str) -> std::io::Result<()> {
    write
        .write_all(format!("{code} {text}\r\n").as_bytes())
        .await?;
    write.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    /// A commit that always accepts — for tests about SMTP flow, not durability.
    struct AcceptAll;
    #[async_trait]
    impl Commit for AcceptAll {
        async fn commit(&self, _message: &ReceivedMessage) -> Result<(), CommitReject> {
            Ok(())
        }
    }

    /// A commit that always refuses — to prove a failed persist becomes `451`.
    struct RejectAll;
    #[async_trait]
    impl Commit for RejectAll {
        async fn commit(&self, _message: &ReceivedMessage) -> Result<(), CommitReject> {
            Err(CommitReject::new(451, "disk full"))
        }
    }

    /// Reads one (possibly multiline) reply and returns its code.
    async fn code<R: AsyncBufRead + Unpin>(r: &mut R) -> u16 {
        loop {
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            let c: u16 = line[..3].parse().unwrap();
            // Final line has a space after the code; continuations have a dash.
            if line.as_bytes().get(3) != Some(&b'-') {
                return c;
            }
        }
    }

    async fn send<W: AsyncWrite + Unpin>(w: &mut W, cmd: &str) {
        w.write_all(cmd.as_bytes()).await.unwrap();
        w.write_all(b"\r\n").await.unwrap();
        w.flush().await.unwrap();
    }

    #[tokio::test]
    async fn a_whole_transaction_yields_the_message() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &AcceptAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO client.test").await;
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "MAIL FROM:<alice@a.com>").await;
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "RCPT TO:<bob@mail.test>").await;
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "DATA").await;
        assert_eq!(code(&mut r).await, 354);
        cw.write_all(b"Subject: hi\r\n\r\nhello\r\n.\r\n")
            .await
            .unwrap();
        cw.flush().await.unwrap();
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "QUIT").await;
        assert_eq!(code(&mut r).await, 221);
        drop(cw);

        let msgs = task.await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].mail_from, "alice@a.com");
        assert_eq!(msgs[0].rcpt_to, vec!["bob@mail.test".to_string()]);
        assert_eq!(msgs[0].data, b"Subject: hi\r\n\r\nhello\r\n");
    }

    #[tokio::test]
    async fn a_failed_commit_answers_451_not_250() {
        // The never-lose contract at the wire: if the durable sink refuses
        // the message, the client must hear 451 (retry later), never a 250.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &RejectAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO c").await;
        code(&mut r).await;
        send(&mut cw, "MAIL FROM:<a@b.com>").await;
        code(&mut r).await;
        send(&mut cw, "RCPT TO:<bob@mail.test>").await;
        code(&mut r).await;
        send(&mut cw, "DATA").await;
        code(&mut r).await;
        cw.write_all(b"body\r\n.\r\n").await.unwrap();
        cw.flush().await.unwrap();
        assert_eq!(code(&mut r).await, 451, "a failed commit must not be a 250");
        send(&mut cw, "QUIT").await;
        assert_eq!(code(&mut r).await, 221);
        drop(cw);
        drop(r);
        // And nothing is reported as accepted.
        assert!(task.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn commands_out_of_order_earn_503() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &AcceptAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO c").await;
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "RCPT TO:<bob@mail.test>").await;
        assert_eq!(code(&mut r).await, 503); // RCPT before MAIL
        send(&mut cw, "MAIL FROM:<a@b.com>").await;
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "DATA").await;
        assert_eq!(code(&mut r).await, 503); // DATA before a recipient
        send(&mut cw, "QUIT").await;
        assert_eq!(code(&mut r).await, 221);
        drop(cw);
        assert!(task.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_recipient_we_dont_host_is_refused() {
        // The open-relay defense: we host mail.test, so mail for
        // somewhere-else.com must be rejected, and nothing gets accepted.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &AcceptAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO c").await;
        code(&mut r).await;
        send(&mut cw, "MAIL FROM:<a@b.com>").await;
        code(&mut r).await;
        send(&mut cw, "RCPT TO:<victim@somewhere-else.com>").await;
        assert_eq!(code(&mut r).await, 550);
        send(&mut cw, "QUIT").await;
        assert_eq!(code(&mut r).await, 221);
        drop(cw);
        drop(r);
        assert!(task.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_null_sender_is_accepted_for_bounces() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &AcceptAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO c").await;
        code(&mut r).await;
        send(&mut cw, "MAIL FROM:<>").await;
        assert_eq!(code(&mut r).await, 250);
        send(&mut cw, "RCPT TO:<bob@mail.test>").await;
        code(&mut r).await;
        send(&mut cw, "DATA").await;
        code(&mut r).await;
        cw.write_all(b"a bounce\r\n.\r\n").await.unwrap();
        cw.flush().await.unwrap();
        assert_eq!(code(&mut r).await, 250);
        drop(cw);
        drop(r); // both halves must drop for the duplex to signal EOF
        let msgs = task.await.unwrap();
        assert_eq!(msgs[0].mail_from, "");
    }

    #[tokio::test]
    async fn dot_stuffing_is_reversed_in_the_body() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &AcceptAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO c").await;
        code(&mut r).await;
        send(&mut cw, "MAIL FROM:<a@b.com>").await;
        code(&mut r).await;
        send(&mut cw, "RCPT TO:<bob@mail.test>").await;
        code(&mut r).await;
        send(&mut cw, "DATA").await;
        code(&mut r).await;
        // Wire has "..secret" (a stuffed ".secret") and ".." (a stuffed ".").
        cw.write_all(b"hi\r\n..secret\r\n..\r\nbye\r\n.\r\n")
            .await
            .unwrap();
        cw.flush().await.unwrap();
        assert_eq!(code(&mut r).await, 250);
        drop(cw);
        drop(r);
        let msgs = task.await.unwrap();
        assert_eq!(msgs[0].data, b"hi\r\n.secret\r\n.\r\nbye\r\n");
    }

    #[tokio::test]
    async fn one_session_can_carry_two_messages() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let policy = crate::server::policy::HostedDomains::new(["mail.test".to_string()]);
        let task = tokio::spawn(async move {
            serve(server, "mail.test", &policy, &AcceptAll)
                .await
                .unwrap()
        });
        let (cr, mut cw) = tokio::io::split(client);
        let mut r = BufReader::new(cr);

        assert_eq!(code(&mut r).await, 220);
        send(&mut cw, "EHLO c").await;
        code(&mut r).await;
        for body in ["one", "two"] {
            send(&mut cw, "MAIL FROM:<a@b.com>").await;
            code(&mut r).await;
            send(&mut cw, "RCPT TO:<bob@mail.test>").await;
            code(&mut r).await;
            send(&mut cw, "DATA").await;
            code(&mut r).await;
            cw.write_all(format!("{body}\r\n.\r\n").as_bytes())
                .await
                .unwrap();
            cw.flush().await.unwrap();
            assert_eq!(code(&mut r).await, 250);
        }
        send(&mut cw, "QUIT").await;
        code(&mut r).await;
        drop(cw);
        let msgs = task.await.unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].data, b"one\r\n");
        assert_eq!(msgs[1].data, b"two\r\n");
    }
}
