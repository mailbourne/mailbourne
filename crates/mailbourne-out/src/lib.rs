//! # mailbourne-out — a message must leave
//!
//! This crate is the irreducible core of email: take responsibility for a
//! message and move it toward its destination, retrying until it is
//! delivered or honestly bounced. Everything else in a mail system exists
//! *around* this act.
//!
//! **Read the modules in order — they are the journey of one message:**
//!
//! | step | module | what happens |
//! |---|---|---|
//! | 1 | [`sign`] | seal it — a DKIM signature over the exact bytes |
//! | 2 | [`route`] | find the door — MX lookup, priorities, fallbacks |
//! | 3 | [`dial`] | knock — TCP to port 25, then STARTTLS |
//! | 4 | [`conversation`] | speak SMTP — EHLO → MAIL → RCPT → DATA → 250 |
//! | 5 | [`queue`] | if not now… — durable store-and-forward |
//! | 6 | [`retry`] | …try again — backoff, 4xx vs 5xx, give-up → bounce |
//!
//! Store-and-forward (steps 5–6) is not an add-on; it *is* email. A `4xx`
//! reply means "not now, try later" and losing the message anyway is the
//! one sin a mail server cannot commit.

pub mod conversation;
pub mod dial;
pub mod queue;
pub mod retry;
pub mod route;
pub mod sign;

use std::time::Duration;

/// Why a whole send attempt could not even reach a dialogue.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// DNS could not tell us where the domain's mail lives.
    #[error(transparent)]
    Route(#[from] route::RouteError),
    /// The domain publishes null MX — it refuses all mail, deliberately.
    #[error("{0} declares it accepts no mail (null MX)")]
    DomainRefusesMail(String),
    /// Every MX host was unreachable. Temporary: requeue and retry.
    #[error("no MX host answered for {domain}: {last}")]
    AllHostsUnreachable {
        /// The domain whose hosts stayed silent.
        domain: String,
        /// The last dial failure, as a sample of what went wrong.
        last: dial::DialError,
    },
    /// The hostname would not resolve to an address to dial.
    #[error("could not resolve {0} to an address")]
    NoAddress(String),
    /// The wire failed mid-dialogue.
    #[error(transparent)]
    Wire(#[from] conversation::ReplyError),
}

/// The whole journey to one specific host: dial, then speak, with
/// opportunistic STARTTLS (verified against the public trust roots).
///
/// This is the direct door used by tests and by `--proof` runs; normal
/// sending goes through [`send`], which picks hosts via MX routing.
///
/// # Errors
/// [`SendError::NoAddress`] / [`SendError::AllHostsUnreachable`] when the
/// host can't be dialed, [`SendError::Wire`] when the dialogue itself
/// breaks. A polite refusal is an [`conversation::Outcome`], not an error.
pub async fn send_to_host(
    host: &str,
    port: u16,
    our_hostname: &str,
    envelope: &mailbourne_core::Envelope,
    message: &mailbourne_core::Message,
) -> Result<conversation::Outcome, SendError> {
    let addr = tokio::net::lookup_host((host, port))
        .await
        .ok()
        .and_then(|mut addrs| addrs.next())
        .ok_or_else(|| SendError::NoAddress(host.to_string()))?;

    let tcp =
        dial::connect(addr, DIAL_TIMEOUT)
            .await
            .map_err(|last| SendError::AllHostsUnreachable {
                domain: host.to_string(),
                last,
            })?;

    let server_name = host.to_string();
    let outcome = conversation::deliver_with_starttls(
        tcp,
        move |stream| async move {
            dial::secure(stream, &server_name, dial::webpki_trust_roots()).await
        },
        our_hostname,
        envelope,
        message,
    )
    .await?;
    Ok(outcome)
}

/// The whole journey by domain: MX routing, then hosts in priority order
/// until one answers, then the dialogue.
///
/// # Errors
/// See [`SendError`] — routing failures, a null-MX domain, silence from
/// every host, or a broken wire. Refusals arrive as
/// [`conversation::Outcome`]s.
pub async fn send(
    our_hostname: &str,
    envelope: &mailbourne_core::Envelope,
    message: &mailbourne_core::Message,
) -> Result<conversation::Outcome, SendError> {
    let domain = envelope
        .rcpt_to
        .first()
        .map(|r| r.domain().to_string())
        .unwrap_or_default();

    let hosts = match route::lookup(&domain).await? {
        route::Route::RefusesMail => return Err(SendError::DomainRefusesMail(domain)),
        route::Route::ToHosts(hosts) => hosts,
    };

    let mut last_dial_error = None;
    for mx in &hosts {
        match send_to_host(&mx.host, 25, our_hostname, envelope, message).await {
            Err(SendError::AllHostsUnreachable { last, .. }) => last_dial_error = Some(last),
            other => return other,
        }
    }
    Err(SendError::AllHostsUnreachable {
        domain,
        last: last_dial_error.expect("at least one host was tried"),
    })
}

const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
