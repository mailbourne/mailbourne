//! # config — the server and its domains
//!
//! The dividing line of the whole system, drawn in TOML: **one `[server]`**
//! (the van — hostname, IP, certificate; everything expensive and shared)
//! and **many `[[domain]]`s** (the letterheads — each with its own DKIM
//! identity and its own [`Mode`]). In the real world inbound often stays
//! with an existing provider (Gmail, Cloudflare Email Routing) while
//! outbound runs here — modes make that hybrid a first-class citizen.
//! A domain the config mentions is a domain mailbourne manages; none is
//! ever off the books.
//!
//! ```toml
//! [server]
//! hostname = "mail.mb.example.com"
//!
//! [[domain]]
//! name = "ds.example.com"
//! mode = "out"                    # sends only; inbound stays where it is
//! dkim_selector = "mb2026"
//! dkim_key = "keys/ds.example.com.pem"
//! ```

use crate::address::EmailAddress;
use serde::Deserialize;

/// Which directions of mail a domain participates in.
///
/// The default is [`Mode::Out`] — the safe posture: mailbourne never
/// claims a domain's inbound (its MX) unless explicitly asked, so an
/// existing Gmail/Cloudflare inbox can never be broken by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Sending only. SPF/DKIM/DMARC required; **MX is left alone** —
    /// inbound stays with the current provider.
    #[default]
    Out,
    /// Receiving only. MX points here; no sending identity needed.
    In,
    /// Full citizen: sending and receiving.
    Both,
}

/// The server itself — the van: one hostname shared by every domain.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// The server's own name — used in SMTP greetings (`EHLO`), as the
    /// PTR target, and as the TLS certificate name. One per server.
    pub hostname: String,
}

/// One managed domain: its name, its direction, its signing identity.
#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    /// The mail domain — the part after `@` in its addresses.
    pub name: String,
    /// Which directions this domain participates in.
    #[serde(default)]
    pub mode: Mode,
    /// DKIM selector (the name before `._domainkey` in DNS).
    pub dkim_selector: Option<String>,
    /// Path to this domain's DKIM private key (PEM).
    pub dkim_key: Option<std::path::PathBuf>,
}

/// The whole configuration: one server, a registry of domains.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The machine's shared identity.
    pub server: ServerConfig,
    /// Every domain this server manages.
    #[serde(default, rename = "domain")]
    pub domains: Vec<DomainConfig>,
}

/// Why a configuration was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The TOML itself didn't parse or a required field is missing.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// The same domain appears twice — ambiguity a mail server must
    /// refuse loudly rather than resolve silently.
    #[error("domain {0} is declared more than once")]
    DuplicateDomain(String),
    /// The file itself could not be read.
    #[error("could not read {path}: {source}")]
    Unreadable {
        /// The path we tried.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

impl Config {
    /// Parses `mailbourne.toml` content.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] for malformed TOML or a missing
    /// `[server]`/`hostname`; [`ConfigError::DuplicateDomain`] when a
    /// domain is declared twice.
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Config =
            toml::from_str(text).map_err(|e| ConfigError::Invalid(e.to_string()))?;

        let mut seen = std::collections::HashSet::new();
        for domain in &config.domains {
            if !seen.insert(domain.name.as_str()) {
                return Err(ConfigError::DuplicateDomain(domain.name.clone()));
            }
        }
        Ok(config)
    }

    /// Loads `mailbourne.toml` from disk.
    ///
    /// Relative `dkim_key` paths are resolved against the config file's own
    /// directory — so a config can travel with its keys ("keys/x.pem" next
    /// to the TOML) and mean the same thing from any working directory.
    ///
    /// # Errors
    /// [`ConfigError::Unreadable`] when the file can't be read, plus
    /// everything [`Config::parse_toml`] refuses.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config = Self::parse_toml(&text)?;

        // Anchor relative key paths to the config's home, not the caller's
        // working directory — the config travels with its keys.
        if let Some(home) = path.parent() {
            for domain in &mut config.domains {
                if let Some(key) = &domain.dkim_key {
                    if key.is_relative() {
                        domain.dkim_key = Some(home.join(key));
                    }
                }
            }
        }
        Ok(config)
    }

    /// Looks up a managed domain by name.
    pub fn domain(&self, name: &str) -> Option<&DomainConfig> {
        self.domains.iter().find(|d| d.name == name)
    }

    /// The managed domain a sender address belongs to, if any —
    /// `proof@ds.example.com` → the `ds.example.com` entry.
    pub fn domain_for_sender(&self, sender: &EmailAddress) -> Option<&DomainConfig> {
        self.domain(sender.domain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_DOMAINS: &str = r#"
        [server]
        hostname = "mail.mb.example.com"

        [[domain]]
        name = "ds.example.com"
        mode = "out"
        dkim_selector = "mb2026"
        dkim_key = "keys/ds.example.com.pem"

        [[domain]]
        name = "mb.example.com"
        mode = "both"
    "#;

    #[test]
    fn parses_the_registry_with_modes() {
        let config = Config::parse_toml(TWO_DOMAINS).unwrap();
        assert_eq!(config.server.hostname, "mail.mb.example.com");
        assert_eq!(config.domains.len(), 2);
        assert_eq!(config.domain("ds.example.com").unwrap().mode, Mode::Out);
        assert_eq!(config.domain("mb.example.com").unwrap().mode, Mode::Both);
    }

    #[test]
    fn mode_defaults_to_out_only() {
        // Safe posture: never claim a domain's inbound unless asked —
        // an existing Gmail/Cloudflare inbox must be unbreakable by accident.
        let config = Config::parse_toml(
            r#"
            [server]
            hostname = "mail.example.com"
            [[domain]]
            name = "example.com"
            "#,
        )
        .unwrap();
        assert_eq!(config.domain("example.com").unwrap().mode, Mode::Out);
    }

    #[test]
    fn a_domain_declared_twice_is_refused() {
        let err = Config::parse_toml(
            r#"
            [server]
            hostname = "mail.example.com"
            [[domain]]
            name = "example.com"
            [[domain]]
            name = "example.com"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateDomain(d) if d == "example.com"));
    }

    #[test]
    fn a_missing_server_section_is_invalid() {
        let err = Config::parse_toml(r#"[[domain]]"#).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn the_sender_address_finds_its_domain() {
        let config = Config::parse_toml(TWO_DOMAINS).unwrap();
        let sender = EmailAddress::parse("proof@ds.example.com").unwrap();
        let domain = config.domain_for_sender(&sender).unwrap();
        assert_eq!(domain.name, "ds.example.com");
        assert_eq!(domain.dkim_selector.as_deref(), Some("mb2026"));
    }

    #[test]
    fn load_reads_a_file_and_anchors_relative_key_paths() {
        let dir = std::env::temp_dir().join("mb-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mailbourne.toml");
        std::fs::write(
            &path,
            r#"
            [server]
            hostname = "mail.example.com"
            [[domain]]
            name = "example.com"
            dkim_selector = "s1"
            dkim_key = "keys/example.pem"
            "#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(
            config.domain("example.com").unwrap().dkim_key.as_deref(),
            Some(dir.join("keys/example.pem").as_path()),
            "relative key paths anchor to the config's directory"
        );
    }

    #[test]
    fn load_leaves_absolute_key_paths_alone() {
        let dir = std::env::temp_dir().join("mb-config-test-abs");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mailbourne.toml");
        std::fs::write(
            &path,
            r#"
            [server]
            hostname = "mail.example.com"
            [[domain]]
            name = "example.com"
            dkim_key = "/etc/keys/example.pem"
            "#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(
            config.domain("example.com").unwrap().dkim_key.as_deref(),
            Some(std::path::Path::new("/etc/keys/example.pem"))
        );
    }

    #[test]
    fn load_reports_a_missing_file_honestly() {
        let err = Config::load(std::path::Path::new("/nowhere/mailbourne.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Unreadable { .. }));
    }

    #[test]
    fn an_unmanaged_sender_domain_finds_nothing() {
        let config = Config::parse_toml(TWO_DOMAINS).unwrap();
        let stranger = EmailAddress::parse("who@elsewhere.org").unwrap();
        assert!(config.domain_for_sender(&stranger).is_none());
    }
}
