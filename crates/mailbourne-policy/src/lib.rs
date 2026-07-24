//! # mailbourne-policy — the decision layer
//!
//! Publicly a policy engine; internally a cyber-defense team that assumes
//! every input is an attack (POLICY.md). It decides how the server answers
//! each step of an SMTP session — accept, or reject with a code. The
//! session consults it; native checks and external-tool adapters will
//! implement the same seam.
//!
//! It starts with the single decision that keeps us from being an **open
//! relay** — which recipients we accept — and grows checks (SPF/DKIM/DMARC
//! verification, rate limiting, greylisting) at each stage from here.

/// What the server should do in response to a protocol event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Proceed.
    Accept,
    /// Refuse, with an SMTP status code and a human reason.
    Reject(u16, String),
}

/// A policy the SMTP session consults. Native and integration checks
/// implement it identically, so the session can't tell them apart.
pub trait Policy: Send + Sync {
    /// At `RCPT TO` — do we accept mail for this recipient?
    ///
    /// The baseline answer must be *only if we host it*: accepting mail for
    /// a domain we don't host is an open relay, which spammers hunt for.
    fn accept_recipient(&self, recipient: &str) -> Verdict;
}

/// The baseline acceptance policy: accept mail only for the domains this
/// server hosts (mode `in` / `both`). Everything else is refused —
/// mailbourne is never an open relay.
pub struct HostedDomains {
    domains: Vec<String>,
}

impl HostedDomains {
    /// Builds from the hosted domain names (matched case-insensitively).
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        Self {
            domains: domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl Policy for HostedDomains {
    fn accept_recipient(&self, recipient: &str) -> Verdict {
        let domain = recipient
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or("")
            .to_ascii_lowercase();
        if !domain.is_empty() && self.domains.iter().any(|d| *d == domain) {
            Verdict::Accept
        } else {
            Verdict::Reject(550, format!("relay not permitted — we don't host {domain}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosted() -> HostedDomains {
        HostedDomains::new(["mb.zebflow.com".to_string(), "id.zebflow.com".to_string()])
    }

    #[test]
    fn a_recipient_at_a_hosted_domain_is_accepted() {
        assert_eq!(
            hosted().accept_recipient("bob@mb.zebflow.com"),
            Verdict::Accept
        );
    }

    #[test]
    fn a_recipient_at_an_unhosted_domain_is_refused_550() {
        // This is the open-relay defense: we must NOT accept mail we don't host.
        match hosted().accept_recipient("victim@somewhere-else.com") {
            Verdict::Reject(code, _) => assert_eq!(code, 550),
            other => panic!("expected 550 reject, got {other:?}"),
        }
    }

    #[test]
    fn domain_matching_is_case_insensitive() {
        assert_eq!(
            hosted().accept_recipient("BOB@MB.ZEBFLOW.COM"),
            Verdict::Accept
        );
    }

    #[test]
    fn a_malformed_recipient_is_refused() {
        assert!(matches!(
            hosted().accept_recipient("no-at-sign"),
            Verdict::Reject(_, _)
        ));
        assert!(matches!(
            hosted().accept_recipient(""),
            Verdict::Reject(_, _)
        ));
    }
}
