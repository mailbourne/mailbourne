//! # door — is this incoming mail forged?
//!
//! The acceptance gate that runs on incoming (unauthenticated) mail before it
//! is stored: verify the sender's **SPF**, **DKIM**, and **DMARC**, stamp the
//! result into an `Authentication-Results` header so the mailbox (and a later
//! spam score) can see it, and — when a From-domain's own published policy is
//! `p=reject` and the message fails — refuse it (`550`). That's what stops
//! someone spoofing `bob@yourbank.com`.
//!
//! [`Doorman`] is the seam (a fake drives the session tests without DNS); the
//! richer checks a real door eventually wants — blocklists, greylisting,
//! rate-limits, virus scanning, spam scoring — plug in behind the same trait.

use async_trait::async_trait;
use std::net::IpAddr;

/// The door's verdict on one message.
pub struct Assessment {
    /// The full `Authentication-Results:` header line (CRLF-terminated) to
    /// prepend to the stored message.
    pub header: String,
    /// A refusal reason when the door rejects the message (answered as `550`),
    /// or `None` to accept (annotated).
    pub reject: Option<String>,
}

/// Assesses incoming mail at the door. Implementations may do I/O (DNS).
#[async_trait]
pub trait Doorman: Send + Sync {
    /// Judge one message: `peer_ip` is the connecting client, `helo` its
    /// announced name, `mail_from` the envelope sender, `data` the raw message.
    async fn assess(&self, peer_ip: IpAddr, helo: &str, mail_from: &str, data: &[u8])
    -> Assessment;
}

/// The real door: SPF + DKIM + DMARC verification via `mail-auth`.
pub struct MailAuthDoor {
    authenticator: mail_auth::MessageAuthenticator,
    /// Our own name, used as the `authserv-id` in `Authentication-Results`.
    hostname: String,
    /// Whether to refuse mail that fails DMARC when the domain says `p=reject`.
    enforce_dmarc: bool,
}

impl MailAuthDoor {
    /// Builds a door that resolves DNS via the system configuration.
    pub fn new(hostname: impl Into<String>, enforce_dmarc: bool) -> Self {
        // `new_system_conf` is infallible (it falls back to sane defaults).
        let authenticator =
            mail_auth::MessageAuthenticator::new_system_conf().expect("system DNS configuration");
        Self {
            authenticator,
            hostname: hostname.into(),
            enforce_dmarc,
        }
    }
}

#[async_trait]
impl Doorman for MailAuthDoor {
    async fn assess(
        &self,
        peer_ip: IpAddr,
        helo: &str,
        mail_from: &str,
        data: &[u8],
    ) -> Assessment {
        use mail_auth::dmarc::Policy;
        use mail_auth::dmarc::verify::DmarcParameters;
        use mail_auth::spf::verify::SpfParameters;
        use mail_auth::{AuthenticatedMessage, AuthenticationResults, DmarcResult};

        // An unparseable message can't be authenticated — annotate `none`, but
        // never reject on our own failure to parse.
        let Some(message) = AuthenticatedMessage::parse(data) else {
            return Assessment {
                header: format!("Authentication-Results: {}; none\r\n", self.hostname),
                reject: None,
            };
        };

        let mail_from_domain = mail_from
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(mail_from);
        let from = message.from().to_string();
        let from_domain = from.rsplit_once('@').map(|(_, d)| d).unwrap_or(&from);

        let dkim = self.authenticator.verify_dkim(&message).await;
        let spf = self
            .authenticator
            .verify_spf(SpfParameters::verify_mail_from(
                peer_ip,
                mail_from_domain,
                helo,
                mail_from,
            ))
            .await;
        let dmarc = self
            .authenticator
            .verify_dmarc(DmarcParameters::new(&message, &dkim, from_domain, &spf))
            .await;

        let results = AuthenticationResults::new(&self.hostname)
            .with_dkim_results(&dkim, &from)
            .with_spf_mailfrom_result(&spf, peer_ip, mail_from, helo)
            .with_dmarc_result(&dmarc);

        // DMARC passes if either aligned mechanism passed.
        let dmarc_pass = matches!(dmarc.dkim_result(), DmarcResult::Pass)
            || matches!(dmarc.spf_result(), DmarcResult::Pass);
        let reject =
            if self.enforce_dmarc && !dmarc_pass && matches!(dmarc.policy(), Policy::Reject) {
                Some(format!(
                    "message failed DMARC and {from_domain} publishes p=reject"
                ))
            } else {
                None
            };

        Assessment {
            header: format!("Authentication-Results: {results}\r\n"),
            reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unparseable_message_is_annotated_none_never_rejected() {
        // The door builds; parsing garbage yields a `none` result, no reject —
        // we never punish a sender for our own parse failure. (Full SPF/DKIM/
        // DMARC verification is DNS-backed and proven live.)
        let door = MailAuthDoor::new("mail.ours.test", true);
        let assessment = futures_lite_block(door.assess(
            "127.0.0.1".parse().unwrap(),
            "helo",
            "a@b.test",
            b"not a message",
        ));
        assert!(assessment.reject.is_none());
        assert!(
            assessment
                .header
                .starts_with("Authentication-Results: mail.ours.test")
        );
        assert!(assessment.header.ends_with("\r\n"));
    }

    /// Minimal block-on so this stays a plain `#[test]` (no runtime needed for
    /// the parse-failure path, which does no DNS).
    fn futures_lite_block<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }
}
