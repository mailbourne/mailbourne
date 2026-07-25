//! # policy — the decision layer
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

/// Acceptance for a server that knows its mailboxes: hosted domains, the
/// [`Accounts`](crate::server::accounts::Accounts) registry, and forward
/// aliases together.
///
/// A recipient is accepted when its domain is hosted **and** it's a real
/// account or a forward alias. A hosted domain with *no* accounts stays a
/// catch-all (accept any local part) — so turning on accounts is an opt-in
/// tightening, never a surprise rejection. Everything else is `550`.
pub struct Acceptance {
    hosted: Vec<String>,
    accounts: crate::server::accounts::Accounts,
    forwards: Vec<String>,
}

impl Acceptance {
    /// Builds from hosted domain names, the account registry, and the
    /// forward-match addresses (all matched case-insensitively).
    pub fn new(
        hosted: impl IntoIterator<Item = String>,
        accounts: crate::server::accounts::Accounts,
        forwards: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            hosted: hosted.into_iter().map(|d| d.to_ascii_lowercase()).collect(),
            accounts,
            forwards: forwards
                .into_iter()
                .map(|f| f.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl Policy for Acceptance {
    fn accept_recipient(&self, recipient: &str) -> Verdict {
        let recipient = recipient.to_ascii_lowercase();
        let domain = recipient.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        if domain.is_empty() || !self.hosted.iter().any(|d| d == domain) {
            return Verdict::Reject(550, format!("relay not permitted — we don't host {domain}"));
        }
        // A real mailbox, or a forward alias, is deliverable.
        if self.accounts.is_recipient(&recipient) || self.forwards.iter().any(|f| *f == recipient) {
            return Verdict::Accept;
        }
        // A hosted domain with no accounts is a catch-all (back-compat).
        if !self.accounts.hosts_domain(domain) {
            return Verdict::Accept;
        }
        Verdict::Reject(550, "no such mailbox here".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::accounts::{Accounts, hash_password};
    use crate::shared::core::config::AccountConfig;

    fn hosted() -> HostedDomains {
        HostedDomains::new(["mb.zebflow.com".to_string(), "id.zebflow.com".to_string()])
    }

    fn account(address: &str) -> AccountConfig {
        AccountConfig {
            address: address.to_string(),
            password_hash: hash_password("pw").unwrap(),
            quota_bytes: 0,
            enabled: true,
        }
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

    #[test]
    fn acceptance_accepts_real_accounts_and_refuses_strangers() {
        // ours.test has accounts → strict; other.test hosted but account-less
        // → catch-all. Both are hosted; neither is an open relay.
        let accounts = Accounts::from_config(&[account("bob@ours.test")]);
        let policy = Acceptance::new(
            ["ours.test".to_string(), "other.test".to_string()],
            accounts,
            ["team@ours.test".to_string()], // a forward alias
        );

        assert_eq!(policy.accept_recipient("bob@ours.test"), Verdict::Accept);
        assert_eq!(policy.accept_recipient("team@ours.test"), Verdict::Accept); // forward
        // Unknown local part at a domain that HAS accounts → refused.
        match policy.accept_recipient("ghost@ours.test") {
            Verdict::Reject(code, _) => assert_eq!(code, 550),
            other => panic!("expected 550, got {other:?}"),
        }
        // Any local part at a hosted domain with NO accounts → catch-all.
        assert_eq!(
            policy.accept_recipient("anyone@other.test"),
            Verdict::Accept
        );
        // A domain we don't host → open-relay refusal.
        assert!(matches!(
            policy.accept_recipient("x@elsewhere.test"),
            Verdict::Reject(550, _)
        ));
    }

    #[test]
    fn acceptance_with_no_accounts_is_a_pure_catch_all() {
        // Back-compat: no accounts configured → behaves like HostedDomains.
        let policy = Acceptance::new(
            ["ours.test".to_string()],
            Accounts::default(),
            Vec::<String>::new(),
        );
        assert_eq!(policy.accept_recipient("anyone@ours.test"), Verdict::Accept);
        assert!(matches!(
            policy.accept_recipient("x@elsewhere.test"),
            Verdict::Reject(550, _)
        ));
    }
}
