//! # config — one schema, three sources
//!
//! Configuration resolves in precedence order: CLI flags, then
//! `MAILBOURNE_*` environment variables, then `/var/mailbourne/
//! mailbourne.toml`, then defaults. Every TOML key has an env twin so
//! containers never need file templating. The generated TOML is heavily
//! commented — the config file doubles as a guided tour.
//!
//! The schema lands here as the engine grows; it starts with the one value
//! nothing can work without.

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The mail domain this server is responsible for (`example.com`).
    /// The only *required* setting — everything else is defaulted or
    /// detected.
    pub domain: String,
    /// The server's own hostname, used in SMTP greetings and DNS records.
    /// Defaults to `mail.<domain>`.
    pub hostname: String,
}

impl Config {
    /// Builds a config from the domain alone, deriving every default.
    pub fn for_domain(domain: impl Into<String>) -> Self {
        let domain = domain.into();
        let hostname = format!("mail.{domain}");
        Self { domain, hostname }
    }
}
