//! # forward — relay an alias onward
//!
//! A [`DeliveryTarget`] that re-mails accepted messages to another address:
//! mail for `bob@ours.com` is relayed on to `bob@gmail.com` through the same
//! outbound engine ([`crate::send`]) — MX routing, TLS, and spool-backed
//! retry all reused.
//!
//! **The bytes are relayed untouched** (only a trace `Received:` header is
//! prepended), so the original DKIM signature survives. That's what carries
//! forwarded mail through the receiver's DMARC check even though SPF can't
//! survive the extra hop — see `ARCHITECTURE.md`/the forwarding notes.
//!
//! Two seams are left open for the deliverability upgrades a serious
//! forwarder eventually wants, so they slot in without a rewrite:
//!
//! - [`ForwardTarget::envelope_sender`] — the envelope return address. Plain
//!   keeps the original sender; **SRS** will rewrite it here so bounces route
//!   back through us and the envelope passes SPF.
//! - [`ForwardTarget::prepare`] — the message handed to the relay. Plain
//!   prepends one `Received:` header; **ARC** will add its signed headers here.
//!
//! Loop safety: a message that already carries too many `Received:` headers
//! is refused rather than relayed into an endless bounce between two servers.

use crate::server::inbound::session::ReceivedMessage;
use crate::server::route::{DeliveryOutcome, DeliveryTarget};
use crate::shared::core::{EmailAddress, Envelope, Message};
use async_trait::async_trait;

/// Past this many `Received:` headers, a message is assumed to be looping.
const DEFAULT_MAX_RECEIVED: usize = 25;

/// Relays accepted mail for matching recipients on to another address.
pub struct ForwardTarget {
    /// Our HELO identity, also stamped into the trace header.
    hostname: String,
    /// `(matched recipient, destination)` pairs; recipients are lowercased.
    rules: Vec<(String, String)>,
    /// Loop guard: refuse a message with at least this many `Received:` hops.
    max_received: usize,
}

impl ForwardTarget {
    /// Builds a forwarder from `(recipient, destination)` rules. Recipient
    /// matching is case-insensitive.
    pub fn new(
        hostname: impl Into<String>,
        rules: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            rules: rules
                .into_iter()
                .map(|(m, d)| (m.to_ascii_lowercase(), d))
                .collect(),
            max_received: DEFAULT_MAX_RECEIVED,
        }
    }

    /// The destination for `recipient`, if any rule matches it.
    fn destination_for(&self, recipient: &str) -> Option<&str> {
        let recipient = recipient.to_ascii_lowercase();
        self.rules
            .iter()
            .find(|(m, _)| *m == recipient)
            .map(|(_, dest)| dest.as_str())
    }

    /// **Seam (SRS).** The envelope return address for the relayed message.
    /// Plain forwarding keeps the original sender verbatim; a future SRS
    /// implementation rewrites it here (needs our domain + a signing secret).
    fn envelope_sender(&self, original_mail_from: &str) -> Option<EmailAddress> {
        EmailAddress::parse(original_mail_from).ok()
    }

    /// **Seam (ARC).** The message bytes handed to the relay. Plain forwarding
    /// prepends a single trace `Received:` header (which also feeds loop
    /// detection); ARC will add its signed headers on top of this, still
    /// leaving the original bytes — and their DKIM seal — untouched below.
    fn prepare(&self, data: &[u8]) -> Vec<u8> {
        let trace = format!("Received: by {} with mailbourne\r\n", self.hostname);
        let mut out = Vec::with_capacity(trace.len() + data.len());
        out.extend_from_slice(trace.as_bytes());
        out.extend_from_slice(data);
        out
    }
}

#[async_trait]
impl DeliveryTarget for ForwardTarget {
    fn name(&self) -> &str {
        "forward"
    }

    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        // Only the recipients we have a rule for get forwarded.
        let destinations: Vec<&str> = message
            .rcpt_to
            .iter()
            .filter_map(|r| self.destination_for(r))
            .collect();
        if destinations.is_empty() {
            return DeliveryOutcome::Delivered; // nothing to forward — a no-op
        }

        // Loop guard, before we put anything else on the wire.
        if received_count(&message.data) >= self.max_received {
            return DeliveryOutcome::Failed(format!(
                "refusing to forward a looping message ({}+ Received headers)",
                self.max_received
            ));
        }

        let sender = match self.envelope_sender(&message.mail_from) {
            Some(sender) => sender,
            None => {
                return DeliveryOutcome::Failed(format!(
                    "cannot forward: unusable envelope sender {:?}",
                    message.mail_from
                ));
            }
        };
        let relayed = Message::from_raw(self.prepare(&message.data));

        for dest in destinations {
            let to = match EmailAddress::parse(dest) {
                Ok(to) => to,
                Err(e) => {
                    return DeliveryOutcome::Failed(format!(
                        "bad forward destination {dest}: {e:?}"
                    ));
                }
            };
            let envelope = Envelope {
                mail_from: sender.clone(),
                rcpt_to: vec![to],
            };
            match crate::send::send(&self.hostname, &envelope, &relayed).await {
                Ok(crate::send::conversation::Outcome::Delivered { .. }) => {}
                Ok(crate::send::conversation::Outcome::Deferred { .. }) => {
                    return DeliveryOutcome::Failed(format!("forward to {dest} deferred (4xx)"));
                }
                // Permanent refusal: for now we retry until the spool gives up;
                // generating a bounce to the original sender comes with SRS.
                Ok(crate::send::conversation::Outcome::Rejected { .. }) => {
                    return DeliveryOutcome::Failed(format!("forward to {dest} rejected (5xx)"));
                }
                Err(e) => return DeliveryOutcome::Failed(format!("forward to {dest} failed: {e}")),
            }
        }
        DeliveryOutcome::Delivered
    }
}

/// Counts `Received:` header lines — the hop count a loop guard watches.
/// Only the header block (before the first blank line) is scanned.
fn received_count(data: &[u8]) -> usize {
    data.split(|&b| b == b'\n')
        .take_while(|line| {
            let end = if line.last() == Some(&b'\r') {
                line.len() - 1
            } else {
                line.len()
            };
            end > 0 // stop at the blank line that ends the headers
        })
        .filter(|line| {
            let lower = String::from_utf8_lossy(line).to_ascii_lowercase();
            lower.starts_with("received:")
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ForwardTarget {
        ForwardTarget::new(
            "mail.ours.test",
            [("bob@ours.test".to_string(), "bob@gmail.test".to_string())],
        )
    }

    fn message(mail_from: &str, rcpt: &[&str], data: &[u8]) -> ReceivedMessage {
        ReceivedMessage {
            mail_from: mail_from.to_string(),
            rcpt_to: rcpt.iter().map(|s| s.to_string()).collect(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn matching_is_case_insensitive_and_specific() {
        let t = target();
        assert_eq!(t.destination_for("bob@ours.test"), Some("bob@gmail.test"));
        assert_eq!(t.destination_for("BOB@Ours.Test"), Some("bob@gmail.test"));
        assert_eq!(t.destination_for("alice@ours.test"), None);
    }

    #[test]
    fn prepare_prepends_a_trace_header_and_keeps_the_original_sealed() {
        let t = target();
        let original = b"From: a@b\r\nSubject: hi\r\n\r\nbody";
        let out = t.prepare(original);
        assert!(out.starts_with(b"Received: by mail.ours.test with mailbourne\r\n"));
        // The original bytes — and their DKIM seal — must survive intact.
        assert!(
            out.ends_with(original),
            "original message must be untouched"
        );
    }

    #[test]
    fn the_envelope_sender_seam_keeps_the_original_for_plain_forwarding() {
        let t = target();
        let sender = t.envelope_sender("alice@external.test").unwrap();
        assert_eq!(sender.to_string(), "alice@external.test");
        assert!(t.envelope_sender("not an address").is_none());
    }

    #[test]
    fn received_headers_are_counted_only_in_the_header_block() {
        let data = b"Received: by x\r\nReceived: by y\r\nFrom: a@b\r\n\r\nReceived: in body";
        assert_eq!(received_count(data), 2, "the body line must not count");
    }

    #[tokio::test]
    async fn a_message_with_no_matching_recipient_is_a_no_op() {
        // Never touches the network: nothing to forward.
        let outcome = target()
            .deliver(&message("a@b.test", &["nobody@ours.test"], b"\r\nx"))
            .await;
        assert!(matches!(outcome, DeliveryOutcome::Delivered));
    }

    #[tokio::test]
    async fn a_looping_message_is_refused_before_relay() {
        // A matching recipient, but the message already has too many hops —
        // refused at the loop guard, before any network I/O.
        let t = ForwardTarget {
            hostname: "mail.ours.test".to_string(),
            rules: vec![("bob@ours.test".to_string(), "bob@gmail.test".to_string())],
            max_received: 2,
        };
        let looping = b"Received: by a\r\nReceived: by b\r\nFrom: x@y\r\n\r\nhi";
        let outcome = t
            .deliver(&message("a@b.test", &["bob@ours.test"], looping))
            .await;
        assert!(matches!(outcome, DeliveryOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn an_unusable_sender_cannot_be_forwarded() {
        // A matching recipient but a sender we can't parse (e.g. the null
        // sender of a bounce) — refused before relay for now.
        let outcome = target()
            .deliver(&message("", &["bob@ours.test"], b"\r\nx"))
            .await;
        assert!(matches!(outcome, DeliveryOutcome::Failed(_)));
    }
}
