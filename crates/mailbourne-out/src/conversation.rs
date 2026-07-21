//! # 4 · conversation — speak SMTP
//!
//! The lock-step dialogue of RFC 5321, in strict order:
//!
//! ```text
//! S: 220 ready            (their greeting)
//! C: EHLO mail.us.com     (introduce ourselves; they list capabilities)
//! C: MAIL FROM:<…>        (envelope sender — where bounces go)
//! C: RCPT TO:<…>          (envelope recipient, may repeat)
//! C: DATA                 (may we send the letter?)
//! S: 354 go ahead
//! C: …message…\r\n.\r\n   (the letter, ended by a lone dot)
//! S: 250 OK               ← responsibility transfers HERE
//! C: QUIT
//! ```
//!
//! Every reply's first digit decides everything: `2xx` success, `3xx` "go
//! on", `4xx` temporary — requeue, `5xx` permanent — bounce. Getting that
//! decision right is this module's whole job; the [`retry`](crate::retry)
//! policy depends on it.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// One reply from an SMTP server: a 3-digit code and its text lines.
///
/// Servers may answer in several lines — a *multiline reply* — using a dash
/// after the code on every line except the last:
///
/// ```text
/// 250-mx.example.com greets you     ← more coming (dash)
/// 250-SIZE 35882577                 ← more coming
/// 250 STARTTLS                      ← final line (space)
/// ```
///
/// All lines carry the same code; the space-vs-dash on each line is the only
/// thing that says "I'm done talking."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The 3-digit status code (`250`, `354`, `421`, `550`, …).
    pub code: u16,
    /// The human-readable text of each line, in order, codes stripped.
    pub lines: Vec<String>,
}

/// What a reply's first digit tells us to do next.
///
/// This tiny enum encodes email's famous resilience: a **temporary** "no"
/// keeps the message safely queued for another try (greylisting counts on
/// it), while only a **permanent** "no" may bounce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// `2xx` — the server accepted; move to the next step.
    Success,
    /// `3xx` — the server says "go on" (e.g. `354` after `DATA`).
    Intermediate,
    /// `4xx` — "not now, try later." Requeue; never bounce on this.
    Temporary,
    /// `5xx` — "no, and don't retry." Bounce honestly.
    Permanent,
}

impl Reply {
    /// Which of the four verdicts this reply's first digit carries.
    pub fn severity(&self) -> Severity {
        match self.code / 100 {
            2 => Severity::Success,
            3 => Severity::Intermediate,
            4 => Severity::Temporary,
            _ => Severity::Permanent,
        }
    }
}

/// Why reading a reply from the wire failed.
#[derive(Debug, thiserror::Error)]
pub enum ReplyError {
    /// The connection ended mid-reply.
    #[error("connection closed while awaiting a reply")]
    ConnectionClosed,
    /// The line did not start with a 3-digit code — not SMTP.
    #[error("malformed reply line: {0:?}")]
    Malformed(String),
    /// The underlying socket failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one complete (possibly multiline) SMTP reply from the server.
///
/// Blocks until the final line — the one with a space after the code —
/// has arrived, and returns every line under one [`Reply`].
///
/// # Errors
/// [`ReplyError::ConnectionClosed`] if the stream ends mid-reply,
/// [`ReplyError::Malformed`] if a line doesn't begin with a 3-digit code,
/// [`ReplyError::Io`] if the socket itself fails.
pub async fn read_reply<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Reply, ReplyError> {
    let mut code: Option<u16> = None;
    let mut lines = Vec::new();

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(ReplyError::ConnectionClosed);
        }
        let line = line.trim_end_matches(['\r', '\n']);

        // Every line starts with the same 3-digit code…
        let digits = line.get(..3).ok_or_else(|| malformed(line))?;
        let line_code: u16 = digits.parse().map_err(|_| malformed(line))?;
        code.get_or_insert(line_code);

        // …followed by '-' (more coming), ' ' (final line), or nothing (final).
        let (is_final, text) = match line.as_bytes().get(3) {
            Some(b'-') => (false, &line[4..]),
            Some(b' ') => (true, &line[4..]),
            None => (true, ""),
            Some(_) => return Err(malformed(line)),
        };
        lines.push(text.to_string());

        if is_final {
            // `code` was set on the first iteration of this loop.
            return Ok(Reply {
                code: code.expect("set on first line"),
                lines,
            });
        }
    }
}

fn malformed(line: &str) -> ReplyError {
    ReplyError::Malformed(line.to_string())
}

/// Where in the dialogue something happened — so a refusal can say
/// *which sentence* the server objected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Their `220` greeting when we connect.
    Greeting,
    /// Our `EHLO` introduction.
    Ehlo,
    /// The envelope sender (`MAIL FROM`).
    MailFrom,
    /// An envelope recipient (`RCPT TO`).
    RcptTo,
    /// Asking permission to send the letter (`DATA`).
    Data,
    /// The letter itself, ended by the lone dot.
    Payload,
    /// Asking to go private (`STARTTLS`).
    StartTls,
}

/// How one delivery attempt ended.
///
/// Note there are *three* endings, not two — because in email "no" comes in
/// two flavors, and confusing them is how servers lose mail:
///
/// - [`Outcome::Delivered`]: their `250` after the payload. Responsibility
///   has transferred to them.
/// - [`Outcome::Deferred`]: a `4xx` — "not now." The message must go back
///   to the queue and try again later (greylisting counts on this).
/// - [`Outcome::Rejected`]: a `5xx` — "never." Bounce honestly; do not retry.
#[derive(Debug)]
pub enum Outcome {
    /// The server accepted the message. The reply is kept for the log line.
    Delivered {
        /// Their final `250` reply.
        reply: Reply,
    },
    /// Temporary refusal — requeue and retry with backoff.
    Deferred {
        /// The step the server deferred at.
        at: Step,
        /// Their `4xx` reply.
        reply: Reply,
    },
    /// Permanent refusal — generate a bounce, never retry.
    Rejected {
        /// The step the server rejected at.
        at: Step,
        /// Their `5xx` reply.
        reply: Reply,
    },
}

/// Runs one complete SMTP delivery attempt over an already-connected stream.
///
/// Speaks the whole dialogue — greeting, `EHLO`, envelope, `DATA`, payload,
/// `QUIT` — and reports how it ended as an [`Outcome`]. The message bytes
/// are made *transparent* on the wire: any line of the letter that starts
/// with a dot gets a second dot prepended (RFC 5321 §4.5.2), so a message
/// containing a lone-dot line can't end the transfer early.
///
/// Takes any async stream, which is what makes this testable without a
/// network and reusable over both plaintext and TLS connections.
///
/// # Errors
/// Returns [`ReplyError`] when the *wire* fails (closed connection,
/// malformed reply). A polite refusal is not an error — it's an [`Outcome`].
pub async fn deliver<S>(
    stream: S,
    our_hostname: &str,
    envelope: &mailbourne_core::Envelope,
    message: &mailbourne_core::Message,
) -> Result<Outcome, ReplyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut chat = tokio::io::BufReader::new(stream);
    match open_dialogue(&mut chat, our_hostname).await? {
        Opening::Refused(outcome) => Ok(outcome),
        Opening::Ready { .. } => finish_dialogue(chat, envelope, message).await,
    }
}

/// Like [`deliver`], but upgrades to TLS via `STARTTLS` when the server
/// offers it — the *opportunistic TLS* every modern receiver expects.
///
/// The upgrade itself is delegated to `upgrade` (in production, a
/// [`rustls`] handshake from [`crate::dial`]; in tests, anything), which is
/// what keeps this choreography testable without certificates:
///
/// ```text
/// C: EHLO us          S: 250-them / 250 STARTTLS   ← they offer
/// C: STARTTLS         S: 220 go ahead
///        ⇅ TLS handshake — the stream transforms ⇅
/// C: EHLO us (again — the pre-TLS introduction no longer counts)
/// C: MAIL FROM… (dialogue continues, now private)
/// ```
///
/// A server that doesn't advertise `STARTTLS` proceeds in plaintext.
///
/// # Errors
/// [`ReplyError`] on wire failures, including a failed TLS handshake
/// (surfaced as [`ReplyError::Io`]). Refusals are [`Outcome`]s, not errors.
pub async fn deliver_with_starttls<S, U, Fut, T>(
    stream: S,
    upgrade: U,
    our_hostname: &str,
    envelope: &mailbourne_core::Envelope,
    message: &mailbourne_core::Message,
) -> Result<Outcome, ReplyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: FnOnce(S) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut chat = tokio::io::BufReader::new(stream);
    let capabilities = match open_dialogue(&mut chat, our_hostname).await? {
        Opening::Refused(outcome) => return Ok(outcome),
        Opening::Ready { capabilities } => capabilities,
    };

    let offers_tls = capabilities
        .iter()
        .any(|cap| cap.eq_ignore_ascii_case("STARTTLS"));
    if !offers_tls {
        // Opportunistic: no offer means we proceed in plaintext rather
        // than fail — the doctor's job is to notice and say so.
        return finish_dialogue(chat, envelope, message).await;
    }

    send_line(&mut chat, "STARTTLS").await?;
    let reply = read_reply(&mut chat).await?;
    if let Some(outcome) = refusal(Step::StartTls, reply, Severity::Success) {
        say_goodbye(&mut chat).await;
        return Ok(outcome);
    }

    // The channel transforms: hand the bare stream to the upgrader…
    let secured = upgrade(chat.into_inner()).await?;
    let mut chat = tokio::io::BufReader::new(secured);

    // …and introduce ourselves again — the plaintext EHLO no longer counts.
    match open_dialogue_after_tls(&mut chat, our_hostname).await? {
        Opening::Refused(outcome) => Ok(outcome),
        Opening::Ready { .. } => finish_dialogue(chat, envelope, message).await,
    }
}

/// The post-upgrade re-introduction: just the second `EHLO` (no greeting —
/// the server already said hello in plaintext).
async fn open_dialogue_after_tls<C>(chat: &mut C, our_hostname: &str) -> Result<Opening, ReplyError>
where
    C: AsyncBufRead + tokio::io::AsyncWrite + Unpin,
{
    send_line(chat, &format!("EHLO {our_hostname}")).await?;
    let ehlo = read_reply(chat).await?;
    if let Some(outcome) = refusal(Step::Ehlo, ehlo.clone(), Severity::Success) {
        say_goodbye(chat).await;
        return Ok(Opening::Refused(outcome));
    }
    Ok(Opening::Ready {
        capabilities: ehlo.lines,
    })
}

/// How the opening (greeting + `EHLO`) ended.
enum Opening {
    /// The server turned us away before the envelope.
    Refused(Outcome),
    /// Introductions done; `capabilities` are the EHLO reply lines.
    Ready { capabilities: Vec<String> },
}

/// Speaks the opening: await their greeting, introduce ourselves with EHLO.
async fn open_dialogue<C>(chat: &mut C, our_hostname: &str) -> Result<Opening, ReplyError>
where
    C: AsyncBufRead + tokio::io::AsyncWrite + Unpin,
{
    let greeting = read_reply(chat).await?;
    if let Some(outcome) = refusal(Step::Greeting, greeting, Severity::Success) {
        say_goodbye(chat).await;
        return Ok(Opening::Refused(outcome));
    }

    send_line(chat, &format!("EHLO {our_hostname}")).await?;
    let ehlo = read_reply(chat).await?;
    if let Some(outcome) = refusal(Step::Ehlo, ehlo.clone(), Severity::Success) {
        say_goodbye(chat).await;
        return Ok(Opening::Refused(outcome));
    }
    Ok(Opening::Ready {
        capabilities: ehlo.lines,
    })
}

/// Speaks the rest: envelope, letter, verdict, goodbye.
async fn finish_dialogue<C>(
    mut chat: C,
    envelope: &mailbourne_core::Envelope,
    message: &mailbourne_core::Message,
) -> Result<Outcome, ReplyError>
where
    C: AsyncBufRead + tokio::io::AsyncWrite + Unpin,
{
    macro_rules! expect {
        ($step:expr, $expected:expr) => {{
            let reply = read_reply(&mut chat).await?;
            if let Some(outcome) = refusal($step, reply, $expected) {
                say_goodbye(&mut chat).await;
                return Ok(outcome);
            }
        }};
    }

    send_line(&mut chat, &format!("MAIL FROM:<{}>", envelope.mail_from)).await?;
    expect!(Step::MailFrom, Severity::Success);

    for rcpt in &envelope.rcpt_to {
        send_line(&mut chat, &format!("RCPT TO:<{rcpt}>")).await?;
        expect!(Step::RcptTo, Severity::Success);
    }

    send_line(&mut chat, "DATA").await?;
    expect!(Step::Data, Severity::Intermediate); // 354: "go ahead"

    write_transparent_payload(&mut chat, message.raw()).await?;

    let reply = read_reply(&mut chat).await?;
    if let Some(outcome) = refusal(Step::Payload, reply.clone(), Severity::Success) {
        say_goodbye(&mut chat).await;
        return Ok(outcome);
    }

    say_goodbye(&mut chat).await;
    Ok(Outcome::Delivered { reply })
}

/// Maps an unexpected reply at `at` into the polite early ending it deserves.
fn refusal(at: Step, reply: Reply, expected: Severity) -> Option<Outcome> {
    let severity = reply.severity();
    if severity == expected {
        return None;
    }
    match severity {
        Severity::Temporary => Some(Outcome::Deferred { at, reply }),
        _ => Some(Outcome::Rejected { at, reply }),
    }
}

async fn send_line<W>(writer: &mut W, line: &str) -> Result<(), ReplyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Writes the letter with SMTP transparency: every line ends in CRLF, any
/// line that starts with a dot gets a second dot prepended, and the whole
/// payload is closed with the lone-dot terminator (RFC 5321 §4.5.2).
async fn write_transparent_payload<W>(writer: &mut W, raw: &[u8]) -> Result<(), ReplyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let segments: Vec<&[u8]> = raw.split(|b| *b == b'\n').collect();
    for (i, segment) in segments.iter().enumerate() {
        let line = segment.strip_suffix(b"\r").unwrap_or(segment);
        // A trailing newline in the letter leaves one empty final segment —
        // that's the end of the letter, not an extra blank line.
        if i == segments.len() - 1 && line.is_empty() {
            break;
        }
        if line.first() == Some(&b'.') {
            writer.write_all(b".").await?;
        }
        writer.write_all(line).await?;
        writer.write_all(b"\r\n").await?;
    }
    writer.write_all(b".\r\n").await?;
    writer.flush().await?;
    Ok(())
}

/// `QUIT`, best-effort: the outcome is already decided, and a server that
/// hangs up without a `221` changes nothing.
async fn say_goodbye<C>(chat: &mut C)
where
    C: AsyncBufRead + tokio::io::AsyncWrite + Unpin,
{
    if send_line(chat, "QUIT").await.is_ok() {
        let _ = read_reply(chat).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    async fn reply_from(wire: &str) -> Result<Reply, ReplyError> {
        let mut reader = BufReader::new(wire.as_bytes());
        read_reply(&mut reader).await
    }

    #[tokio::test]
    async fn reads_a_single_line_reply() {
        let reply = reply_from("250 OK\r\n").await.unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines, vec!["OK"]);
    }

    #[tokio::test]
    async fn reads_a_multiline_reply_as_one_reply() {
        let wire = "250-mx.example.com greets you\r\n250-SIZE 35882577\r\n250 STARTTLS\r\n";
        let reply = reply_from(wire).await.unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(
            reply.lines,
            vec!["mx.example.com greets you", "SIZE 35882577", "STARTTLS"]
        );
    }

    #[tokio::test]
    async fn a_lone_dash_line_keeps_waiting_until_the_final_space_line() {
        // The reply is not complete after "250-first"; only "250 done" ends it.
        let wire = "250-first\r\n250 done\r\n";
        let reply = reply_from(wire).await.unwrap();
        assert_eq!(reply.lines.len(), 2);
    }

    #[tokio::test]
    async fn rejects_a_line_without_a_numeric_code() {
        let err = reply_from("hello there\r\n").await.unwrap_err();
        assert!(matches!(err, ReplyError::Malformed(_)));
    }

    #[tokio::test]
    async fn reports_a_connection_that_closes_mid_reply() {
        // Dash promises more lines, but the stream ends.
        let err = reply_from("250-more coming\r\n").await.unwrap_err();
        assert!(matches!(err, ReplyError::ConnectionClosed));
    }

    #[test]
    fn first_digit_decides_the_verdict() {
        let verdict = |code| {
            Reply {
                code,
                lines: vec![],
            }
            .severity()
        };
        assert_eq!(verdict(250), Severity::Success);
        assert_eq!(verdict(354), Severity::Intermediate);
        assert_eq!(verdict(421), Severity::Temporary); // "not now" — requeue
        assert_eq!(verdict(550), Severity::Permanent); // "never" — bounce
    }

    // ── the full dialogue, against a scripted fake MX ────────────────────

    use mailbourne_core::{EmailAddress, Envelope, Message};
    use tokio::io::{AsyncWriteExt, BufReader as TokioBufReader, DuplexStream};

    /// What the fake server replies at each step. Defaults are a friendly MX.
    struct MxScript {
        greeting: &'static str,
        ehlo: &'static str,
        mail: &'static str,
        rcpt: &'static str,
        data: &'static str,
        after_payload: &'static str,
        starttls: &'static str,
    }

    impl Default for MxScript {
        fn default() -> Self {
            Self {
                greeting: "220 fake.mx ready\r\n",
                ehlo: "250-fake.mx greets you\r\n250 OK\r\n",
                mail: "250 sender ok\r\n",
                rcpt: "250 recipient ok\r\n",
                data: "354 go ahead\r\n",
                after_payload: "250 queued as 42\r\n",
                starttls: "220 go ahead, let's go private\r\n",
            }
        }
    }

    /// Everything the fake server saw: command lines, and the raw payload
    /// lines exactly as they crossed the wire (dot-stuffing intact).
    struct MxLog {
        commands: Vec<String>,
        payload_wire: Vec<String>,
    }

    /// Plays the server side of the dialogue per `script`, recording it all.
    async fn fake_mx(stream: DuplexStream, script: MxScript) -> MxLog {
        let mut reader = TokioBufReader::new(stream);
        let mut commands = Vec::new();
        let mut payload_wire = Vec::new();

        reader
            .get_mut()
            .write_all(script.greeting.as_bytes())
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let upper = line.to_uppercase();
            commands.push(line.clone());

            let reply: &str = if upper.starts_with("EHLO") {
                script.ehlo
            } else if upper.starts_with("STARTTLS") {
                script.starttls
            } else if upper.starts_with("MAIL") {
                script.mail
            } else if upper.starts_with("RCPT") {
                script.rcpt
            } else if upper.starts_with("DATA") {
                script.data
            } else if upper.starts_with("QUIT") {
                reader.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                break;
            } else {
                "500 what\r\n"
            };
            reader.get_mut().write_all(reply.as_bytes()).await.unwrap();

            if upper.starts_with("DATA") && script.data.starts_with("354") {
                loop {
                    let mut pline = String::new();
                    if reader.read_line(&mut pline).await.unwrap() == 0 {
                        break;
                    }
                    let pline = pline.trim_end_matches(['\r', '\n']).to_string();
                    if pline == "." {
                        break;
                    }
                    payload_wire.push(pline);
                }
                reader
                    .get_mut()
                    .write_all(script.after_payload.as_bytes())
                    .await
                    .unwrap();
            }
        }

        MxLog {
            commands,
            payload_wire,
        }
    }

    fn envelope(from: &str, to: &str) -> Envelope {
        Envelope {
            mail_from: EmailAddress::parse(from).unwrap(),
            rcpt_to: vec![EmailAddress::parse(to).unwrap()],
        }
    }

    /// Runs `deliver` against a fake MX and returns (outcome, what it saw).
    async fn attempt(script: MxScript, message: &[u8]) -> (Result<Outcome, ReplyError>, MxLog) {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_mx(server_side, script));
        let outcome = deliver(
            client_side,
            "mail.us.example",
            &envelope("alice@us.example", "bob@fake.mx"),
            &Message::from_raw(message.to_vec()),
        )
        .await;
        (outcome, server.await.unwrap())
    }

    #[tokio::test]
    async fn a_friendly_server_gets_the_whole_dialogue_and_the_letter() {
        let (outcome, log) = attempt(MxScript::default(), b"Subject: hi\r\n\r\nhello\r\n").await;

        assert!(matches!(outcome.unwrap(), Outcome::Delivered { .. }));
        assert_eq!(log.commands[0], "EHLO mail.us.example");
        assert_eq!(log.commands[1], "MAIL FROM:<alice@us.example>");
        assert_eq!(log.commands[2], "RCPT TO:<bob@fake.mx>");
        assert_eq!(log.commands[3], "DATA");
        assert_eq!(log.commands[4], "QUIT");
        assert_eq!(log.payload_wire, vec!["Subject: hi", "", "hello"]);
    }

    #[tokio::test]
    async fn a_line_starting_with_a_dot_is_stuffed_on_the_wire() {
        // A letter containing a ".secret" line must not end the transfer:
        // on the wire it travels as "..secret" (RFC 5321 §4.5.2).
        let (outcome, log) = attempt(MxScript::default(), b"hi\r\n.secret\r\nbye\r\n").await;

        assert!(matches!(outcome.unwrap(), Outcome::Delivered { .. }));
        assert_eq!(log.payload_wire, vec!["hi", "..secret", "bye"]);
    }

    #[tokio::test]
    async fn a_letter_without_a_final_newline_still_terminates_cleanly() {
        let (outcome, log) = attempt(MxScript::default(), b"no trailing newline").await;

        assert!(matches!(outcome.unwrap(), Outcome::Delivered { .. }));
        assert_eq!(log.payload_wire, vec!["no trailing newline"]);
    }

    #[tokio::test]
    async fn a_4xx_at_rcpt_defers_for_retry() {
        let script = MxScript {
            rcpt: "450 greylisted, come back later\r\n",
            ..MxScript::default()
        };
        let (outcome, log) = attempt(script, b"x\r\n").await;

        match outcome.unwrap() {
            Outcome::Deferred { at, reply } => {
                assert_eq!(at, Step::RcptTo);
                assert_eq!(reply.code, 450);
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
        // We still said goodbye politely.
        assert_eq!(log.commands.last().unwrap(), "QUIT");
    }

    #[tokio::test]
    async fn a_5xx_at_mail_from_rejects_permanently() {
        let script = MxScript {
            mail: "550 we do not like you\r\n",
            ..MxScript::default()
        };
        let (outcome, _log) = attempt(script, b"x\r\n").await;

        match outcome.unwrap() {
            Outcome::Rejected { at, reply } => {
                assert_eq!(at, Step::MailFrom);
                assert_eq!(reply.code, 550);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // ── STARTTLS choreography (upgrade mechanics injected, so no certs) ──

    /// Runs `deliver_with_starttls` with an identity "upgrade" — the stream
    /// stays the same, which isolates the *choreography* under test.
    async fn attempt_tls(script: MxScript, message: &[u8]) -> (Result<Outcome, ReplyError>, MxLog) {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_mx(server_side, script));
        let outcome = deliver_with_starttls(
            client_side,
            |stream| async move { Ok::<_, std::io::Error>(stream) },
            "mail.us.example",
            &envelope("alice@us.example", "bob@fake.mx"),
            &mailbourne_core::Message::from_raw(message.to_vec()),
        )
        .await;
        (outcome, server.await.unwrap())
    }

    #[tokio::test]
    async fn starttls_is_negotiated_when_the_server_offers_it() {
        let script = MxScript {
            ehlo: "250-fake.mx greets you\r\n250-STARTTLS\r\n250 OK\r\n",
            ..MxScript::default()
        };
        let (outcome, log) = attempt_tls(script, b"x\r\n").await;

        assert!(matches!(outcome.unwrap(), Outcome::Delivered { .. }));
        // EHLO, then STARTTLS, then EHLO *again* — the pre-TLS introduction
        // no longer counts once the channel transforms.
        assert_eq!(log.commands[0], "EHLO mail.us.example");
        assert_eq!(log.commands[1], "STARTTLS");
        assert_eq!(log.commands[2], "EHLO mail.us.example");
        assert_eq!(log.commands[3], "MAIL FROM:<alice@us.example>");
    }

    #[tokio::test]
    async fn plaintext_continues_when_the_server_never_offers_tls() {
        // Default script advertises no STARTTLS — opportunistic TLS means
        // we proceed rather than fail, and never send the command.
        let (outcome, log) = attempt_tls(MxScript::default(), b"x\r\n").await;

        assert!(matches!(outcome.unwrap(), Outcome::Delivered { .. }));
        assert!(log.commands.iter().all(|c| c != "STARTTLS"));
    }

    #[tokio::test]
    async fn a_4xx_to_starttls_defers_the_attempt() {
        let script = MxScript {
            ehlo: "250-fake.mx greets you\r\n250 STARTTLS\r\n",
            starttls: "454 TLS not available right now\r\n",
            ..MxScript::default()
        };
        let (outcome, _log) = attempt_tls(script, b"x\r\n").await;

        match outcome.unwrap() {
            Outcome::Deferred { at, reply } => {
                assert_eq!(at, Step::StartTls);
                assert_eq!(reply.code, 454);
            }
            other => panic!("expected Deferred at StartTls, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_hostile_greeting_rejects_at_the_door() {
        let script = MxScript {
            greeting: "554 go away\r\n",
            ..MxScript::default()
        };
        let (outcome, _log) = attempt(script, b"x\r\n").await;

        match outcome.unwrap() {
            Outcome::Rejected { at, reply } => {
                assert_eq!(at, Step::Greeting);
                assert_eq!(reply.code, 554);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
