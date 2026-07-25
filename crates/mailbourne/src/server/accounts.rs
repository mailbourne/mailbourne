//! # accounts — who really has a mailbox here
//!
//! The registry of real mailbox accounts: an address, an Argon2-hashed
//! password (never the password itself), a quota, and an enabled flag. Two
//! jobs hang off it:
//!
//! - **recipient validation** — [`Accounts::is_recipient`] answers "is this a
//!   real, active mailbox?", so the server can refuse mail for made-up local
//!   parts instead of storing junk for `anything@ours.com`;
//! - **authentication** — [`Accounts::verify`] checks a login for SMTP AUTH
//!   (submission), the thing that lets a client send *through* mailbourne.
//!
//! Passwords are hashed with Argon2id (the current password-hashing standard);
//! [`hash_password`] is what the account-management commands call, and the
//! stored PHC string is all that ever touches disk.

use crate::shared::core::config::AccountConfig;

/// Why an account operation failed.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// Hashing the password failed (effectively only under RNG failure).
    #[error("could not hash password: {0}")]
    Hash(String),
}

/// One resolved account. The password hash is private — callers verify
/// through [`Accounts::verify`], they never read the hash.
#[derive(Debug, Clone)]
pub struct Account {
    /// The mailbox address, lowercased for matching.
    pub address: String,
    /// Per-mailbox byte quota; `0` = unlimited.
    pub quota_bytes: u64,
    /// Whether the account is active.
    pub enabled: bool,
    password_hash: String,
}

/// The set of mailbox accounts this server hosts.
#[derive(Debug, Clone, Default)]
pub struct Accounts {
    entries: Vec<Account>,
}

impl Accounts {
    /// Builds the registry from parsed config entries.
    pub fn from_config(configs: &[AccountConfig]) -> Self {
        Self {
            entries: configs
                .iter()
                .map(|c| Account {
                    address: c.address.to_ascii_lowercase(),
                    quota_bytes: c.quota_bytes,
                    enabled: c.enabled,
                    password_hash: c.password_hash.clone(),
                })
                .collect(),
        }
    }

    /// The account for `address`, if one exists (case-insensitive).
    pub fn lookup(&self, address: &str) -> Option<&Account> {
        let address = address.to_ascii_lowercase();
        self.entries.iter().find(|a| a.address == address)
    }

    /// Whether any accounts are configured at all. When empty, the server
    /// keeps its older catch-all behaviour (accept any local part at a hosted
    /// domain) so existing setups don't suddenly reject mail.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `address` is a real, active mailbox we can deliver to.
    pub fn is_recipient(&self, address: &str) -> bool {
        self.lookup(address).is_some_and(|a| a.enabled)
    }

    /// Whether any account belongs to `domain` (lowercased). A hosted domain
    /// with no accounts stays a catch-all; one *with* accounts is strict.
    pub fn hosts_domain(&self, domain: &str) -> bool {
        let suffix = format!("@{}", domain.to_ascii_lowercase());
        self.entries.iter().any(|a| a.address.ends_with(&suffix))
    }

    /// Verifies an SMTP AUTH login: the account must exist, be enabled, and
    /// the password must match its stored hash.
    pub fn verify(&self, address: &str, password: &str) -> bool {
        match self.lookup(address) {
            Some(account) if account.enabled => verify_password(password, &account.password_hash),
            _ => false,
        }
    }
}

/// Hashes a plaintext password into an Argon2id PHC string, ready to store.
///
/// # Errors
/// [`AccountError::Hash`] if hashing fails (effectively only on RNG failure).
pub fn hash_password(password: &str) -> Result<String, AccountError> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AccountError::Hash(e.to_string()))
}

/// Verifies a plaintext password against a stored PHC hash. A malformed hash
/// is treated as a (safe) non-match.
fn verify_password(password: &str, phc: &str) -> bool {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(address: &str, password: &str, enabled: bool) -> AccountConfig {
        AccountConfig {
            address: address.to_string(),
            password_hash: hash_password(password).unwrap(),
            quota_bytes: 0,
            enabled,
        }
    }

    #[test]
    fn a_password_verifies_only_against_its_own_hash() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong horse", &hash));
        // A hash is never the password, and never predictable.
        assert!(hash.starts_with("$argon2"));
        assert_ne!(hash, hash_password("correct horse").unwrap(), "salted");
    }

    #[test]
    fn a_malformed_hash_is_a_safe_non_match() {
        assert!(!verify_password("anything", "not a real hash"));
    }

    #[test]
    fn the_registry_authenticates_the_right_logins_only() {
        let accounts = Accounts::from_config(&[
            account("Bob@Ours.com", "s3cret", true),
            account("suspended@ours.com", "s3cret", false),
        ]);

        // Case-insensitive address, correct password → in.
        assert!(accounts.verify("bob@ours.com", "s3cret"));
        assert!(!accounts.verify("bob@ours.com", "guess"), "wrong password");
        assert!(!accounts.verify("suspended@ours.com", "s3cret"), "disabled");
        assert!(!accounts.verify("ghost@ours.com", "s3cret"), "unknown");
    }

    #[test]
    fn recipient_validation_follows_existence_and_enabled() {
        let accounts = Accounts::from_config(&[
            account("bob@ours.com", "pw", true),
            account("gone@ours.com", "pw", false),
        ]);
        assert!(accounts.is_recipient("BOB@ours.com"));
        assert!(
            !accounts.is_recipient("gone@ours.com"),
            "disabled isn't a recipient"
        );
        assert!(!accounts.is_recipient("ghost@ours.com"));
        assert!(!accounts.is_empty());
        assert!(Accounts::default().is_empty());
    }
}
