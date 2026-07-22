//! # identity — who is this message sent as?
//!
//! Before a send, three sources negotiate the sending identity: explicit
//! CLI flags (always win), the domain registry in `mailbourne.toml`
//! (the ergonomic path — the right DKIM key found by the `From` domain
//! automatically), and conventions (hostname defaults to
//! `mail.<sender-domain>` when nobody says otherwise).
//!
//! The resolution is a pure function — no I/O, fully testable — and it
//! returns *notes* alongside the answer: the friendly one-liners the CLI
//! prints so nothing about the decision is ever silent.

use mailbourne_core::EmailAddress;
use mailbourne_core::config::{Config, Mode};

/// A resolved DKIM signing identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimIdentity {
    /// The signing domain (`d=`).
    pub domain: String,
    /// The selector (`s=`).
    pub selector: String,
    /// Where the private key lives.
    pub key_path: std::path::PathBuf,
}

/// Everything a send needs to know about itself, plus the friendly notes
/// explaining how it was decided.
#[derive(Debug, Clone)]
pub struct SendIdentity {
    /// Our HELO name for this send.
    pub hostname: String,
    /// The seal to apply, when one could be resolved.
    pub dkim: Option<DkimIdentity>,
    /// Human lines for the CLI to print — how the decision was made,
    /// and any gentle nudges (unregistered domain, missing key, …).
    pub notes: Vec<String>,
}

/// Flags the user gave on the command line — always win over the registry.
#[derive(Debug, Default)]
pub struct Overrides {
    /// `--hostname`
    pub hostname: Option<String>,
    /// `--dkim-domain`
    pub dkim_domain: Option<String>,
    /// `--dkim-selector`
    pub dkim_selector: Option<String>,
    /// `--dkim-key`
    pub dkim_key: Option<std::path::PathBuf>,
}

/// Resolves the sending identity for `from`, negotiating flags, registry,
/// and convention (in that order of authority).
pub fn resolve(
    config: Option<&Config>,
    from: &EmailAddress,
    overrides: &Overrides,
) -> SendIdentity {
    let mut notes = Vec::new();
    let registered = config.and_then(|c| c.domain_for_sender(from));

    // Hostname: flag > registry (server-wide) > convention.
    let hostname = overrides
        .hostname
        .clone()
        .or_else(|| {
            registered
                .is_some()
                .then(|| config.map(|c| c.server.hostname.clone()))
                .flatten()
        })
        .unwrap_or_else(|| format!("mail.{}", from.domain()));

    // DKIM: explicit flags always win.
    let dkim =
        if let (Some(selector), Some(key_path)) = (&overrides.dkim_selector, &overrides.dkim_key) {
            Some(DkimIdentity {
                domain: overrides
                    .dkim_domain
                    .clone()
                    .unwrap_or_else(|| from.domain().to_string()),
                selector: selector.clone(),
                key_path: key_path.clone(),
            })
        } else if let Some(domain) = registered {
            if domain.mode == Mode::In {
                notes.push(format!(
                    "heads-up: {} is registered receive-only (\"in\") — sending anyway, \
                 but reckon it wants mode = \"out\" or \"both\"?",
                    domain.name
                ));
            }
            match (&domain.dkim_selector, &domain.dkim_key) {
                (Some(selector), Some(key_path)) => {
                    notes.push(format!(
                        "signing as {} via the registry (selector {})",
                        domain.name, selector
                    ));
                    Some(DkimIdentity {
                        domain: domain.name.clone(),
                        selector: selector.clone(),
                        key_path: key_path.clone(),
                    })
                }
                _ => {
                    notes.push(format!(
                        "{} is registered but has no DKIM identity yet — sending \
                     unsigned. mint one with: mailbourne domain keygen {}",
                        domain.name, domain.name
                    ));
                    None
                }
            }
        } else {
            if config.is_some() {
                notes.push(format!(
                    "heads-up: {} isn't in the registry — sending with flags/conventions \
                 only. adopt it with: mailbourne domain add {}",
                    from.domain(),
                    from.domain()
                ));
            }
            None
        };

    SendIdentity {
        hostname,
        dkim,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Config {
        Config::parse_toml(
            r#"
            [server]
            hostname = "mail.mb.example.com"

            [[domain]]
            name = "ds.example.com"
            mode = "out"
            dkim_selector = "mb2026"
            dkim_key = "/keys/ds.pem"

            [[domain]]
            name = "bare.example.com"
            mode = "out"

            [[domain]]
            name = "inbox.example.com"
            mode = "in"
            dkim_selector = "s"
            dkim_key = "/keys/inbox.pem"
            "#,
        )
        .unwrap()
    }

    fn addr(s: &str) -> EmailAddress {
        EmailAddress::parse(s).unwrap()
    }

    #[test]
    fn the_registry_supplies_the_signing_identity() {
        let config = registry();
        let id = resolve(
            Some(&config),
            &addr("proof@ds.example.com"),
            &Overrides::default(),
        );

        assert_eq!(id.hostname, "mail.mb.example.com");
        let dkim = id.dkim.unwrap();
        assert_eq!(dkim.domain, "ds.example.com");
        assert_eq!(dkim.selector, "mb2026");
        assert_eq!(dkim.key_path, std::path::PathBuf::from("/keys/ds.pem"));
    }

    #[test]
    fn flags_override_the_registry() {
        let config = registry();
        let id = resolve(
            Some(&config),
            &addr("proof@ds.example.com"),
            &Overrides {
                hostname: Some("mail.other.example".into()),
                dkim_selector: Some("flagsel".into()),
                dkim_key: Some("/tmp/flag.pem".into()),
                dkim_domain: None,
            },
        );

        assert_eq!(id.hostname, "mail.other.example");
        let dkim = id.dkim.unwrap();
        assert_eq!(dkim.selector, "flagsel");
        assert_eq!(dkim.key_path, std::path::PathBuf::from("/tmp/flag.pem"));
        // --dkim-domain unset: the signing domain follows the sender.
        assert_eq!(dkim.domain, "ds.example.com");
    }

    #[test]
    fn a_registered_domain_without_a_key_notes_the_gap() {
        let config = registry();
        let id = resolve(
            Some(&config),
            &addr("x@bare.example.com"),
            &Overrides::default(),
        );

        assert!(id.dkim.is_none());
        assert!(
            id.notes.iter().any(|n| n.contains("keygen")),
            "the note should point at the fix: {:?}",
            id.notes
        );
    }

    #[test]
    fn an_unregistered_sender_gets_a_heads_up() {
        let config = registry();
        let id = resolve(
            Some(&config),
            &addr("x@stranger.org"),
            &Overrides::default(),
        );

        assert!(id.dkim.is_none());
        assert!(
            id.notes.iter().any(|n| n.contains("stranger.org")),
            "the note should name the unregistered domain: {:?}",
            id.notes
        );
        // No registry hostname claim for strangers — convention applies.
        assert_eq!(id.hostname, "mail.stranger.org");
    }

    #[test]
    fn a_receive_only_domain_still_sends_but_gets_a_nudge() {
        let config = registry();
        let id = resolve(
            Some(&config),
            &addr("x@inbox.example.com"),
            &Overrides::default(),
        );

        // Labor pragmatism: she ships — the send proceeds, signed.
        assert!(id.dkim.is_some());
        assert!(
            id.notes.iter().any(|n| n.contains("receive-only")),
            "the nudge should mention the mode: {:?}",
            id.notes
        );
    }

    #[test]
    fn no_config_means_convention_and_silence() {
        let id = resolve(None, &addr("x@lone.example.com"), &Overrides::default());

        assert_eq!(id.hostname, "mail.lone.example.com");
        assert!(id.dkim.is_none());
        assert!(id.notes.is_empty(), "no config, no chatter: {:?}", id.notes);
    }
}
