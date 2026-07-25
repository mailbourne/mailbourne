//! # outbound — relay an authenticated user's mail
//!
//! Submission's delivery target: when a logged-in client (Thunderbird, Gmail's
//! "send mail as", …) hands us a message to send, we DKIM-sign it as the
//! sender's domain and relay it through the outbound engine ([`crate::send`])
//! — MX routing, TLS, and spool-backed retry all reused. This is what makes
//! mailbourne usable *as* an SMTP server you point a mail client at.
//!
//! It only ever runs for **authenticated** sessions (the session routes a
//! logged-in sender's mail here instead of to the local mailbox), so relaying
//! to anywhere is submission, never an open relay.

use crate::server::inbound::session::ReceivedMessage;
use crate::server::route::{DeliveryOutcome, DeliveryTarget};
use crate::shared::core::config::Config;
use crate::shared::core::{EmailAddress, Envelope, Message};
use crate::shared::identity::{self, Overrides};
use async_trait::async_trait;

/// Relays authenticated submissions to the world, signed as their domain.
pub struct OutboundTarget {
    /// The registry, for the sender domain's HELO identity and DKIM key.
    config: Config,
}

impl OutboundTarget {
    /// Builds the relay from the config registry.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// DKIM-signs `data` as the sender's domain when we hold a key for it;
    /// otherwise passes the message through unsigned. Returns the message to
    /// relay and the HELO name to relay under.
    fn sign(&self, from: &EmailAddress, data: &[u8]) -> (Message, String) {
        let overrides = Overrides {
            hostname: None,
            dkim_domain: None,
            dkim_selector: None,
            dkim_key: None,
        };
        let identity = identity::resolve(Some(&self.config), from, &overrides);
        let message = Message::from_raw(data.to_vec());
        if let Some(dkim) = &identity.dkim {
            if let Ok(pem) = std::fs::read_to_string(&dkim.key_path) {
                if let Ok(signed) =
                    crate::send::sign::dkim_sign(&message, &dkim.domain, &dkim.selector, &pem)
                {
                    return (signed, identity.hostname);
                }
            }
        }
        (message, identity.hostname)
    }
}

#[async_trait]
impl DeliveryTarget for OutboundTarget {
    fn name(&self) -> &str {
        "outbound"
    }

    async fn deliver(&self, message: &ReceivedMessage) -> DeliveryOutcome {
        let from = match EmailAddress::parse(&message.mail_from) {
            Ok(from) => from,
            Err(_) => {
                return DeliveryOutcome::Failed(format!(
                    "submission has an unusable sender {:?}",
                    message.mail_from
                ));
            }
        };
        let (signed, helo) = self.sign(&from, &message.data);

        for rcpt in &message.rcpt_to {
            let to = match EmailAddress::parse(rcpt) {
                Ok(to) => to,
                Err(e) => return DeliveryOutcome::Failed(format!("bad recipient {rcpt}: {e:?}")),
            };
            let envelope = Envelope {
                mail_from: from.clone(),
                rcpt_to: vec![to],
            };
            match crate::send::send(&helo, &envelope, &signed).await {
                Ok(crate::send::conversation::Outcome::Delivered { .. }) => {}
                Ok(crate::send::conversation::Outcome::Deferred { .. }) => {
                    return DeliveryOutcome::Failed(format!("relay to {rcpt} deferred (4xx)"));
                }
                Ok(crate::send::conversation::Outcome::Rejected { .. }) => {
                    return DeliveryOutcome::Failed(format!("relay to {rcpt} rejected (5xx)"));
                }
                Err(e) => return DeliveryOutcome::Failed(format!("relay to {rcpt} failed: {e}")),
            }
        }
        DeliveryOutcome::Delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_signs_as_the_senders_domain_when_a_key_is_configured() {
        // A real (throwaway) key on disk, registered for ours.test.
        let pair = crate::shared::dkim::generate_dkim_keypair().unwrap();
        let key_path = std::env::temp_dir().join(format!(
            "mb-outbound-{}.pem",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&key_path, &pair.private_key_pem).unwrap();

        let toml = format!(
            "[server]\nhostname = \"mail.ours.test\"\n\n[[domain]]\nname = \"ours.test\"\nmode = \"both\"\ndkim_selector = \"s1\"\ndkim_key = \"{}\"\n",
            key_path.display()
        );
        let config = Config::parse_toml(&toml).unwrap();
        let target = OutboundTarget::new(config);

        let from = EmailAddress::parse("bob@ours.test").unwrap();
        let (signed, _) = target.sign(&from, b"From: bob@ours.test\r\nSubject: hi\r\n\r\nbody");
        assert!(
            signed.raw().starts_with(b"DKIM-Signature:"),
            "a configured domain's mail must be signed"
        );
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn it_relays_unsigned_when_the_domain_has_no_key() {
        // ours.test is hosted but has no DKIM key; a stranger domain has none
        // either — both relay unsigned rather than fail.
        let config = Config::parse_toml("[server]\nhostname = \"mail.ours.test\"\n").unwrap();
        let target = OutboundTarget::new(config);
        let from = EmailAddress::parse("bob@elsewhere.test").unwrap();
        let original = b"From: bob@elsewhere.test\r\n\r\nbody";
        let (message, _) = target.sign(&from, original);
        assert_eq!(
            message.raw(),
            original,
            "unsigned mail passes through untouched"
        );
    }
}
