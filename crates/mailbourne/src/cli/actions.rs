//! # actions — the side effects behind the CLI verbs
//!
//! The small pieces of "do a thing to the filesystem" that both the flat
//! commands (`mailbourne domain add`) and the interactive console share, so
//! registering a domain means the same thing however you reach it. The pure
//! config text edits live in [`crate::shared::core::edit`]; this is the I/O
//! layer that wraps them (mint a key, write a file) — kept here so the two
//! front ends can't drift apart.

use std::path::Path;

/// The freshly-minted signing identity for a new domain: where its private
/// key was written (relative to the config) and the public record to publish.
pub struct MintedKey {
    /// The `dkim_key` value to store in the config (e.g. `keys/x.pem`),
    /// relative to the config file so it travels with it.
    pub rel_key: String,
    /// The DKIM selector chosen for the key.
    pub selector: String,
    /// The `v=DKIM1;...` TXT value to paste at the DNS provider.
    pub dns_record_value: String,
}

/// Mints a fresh DKIM keypair for `name`, writes the private half next to
/// `config_path` (in `keys/<name>.pem`, mode 600), and returns the relative
/// path plus the public record to publish. The single source of truth for
/// "give this domain a signing key", shared by the console and the CLI.
///
/// # Errors
/// A human-readable message if the key can't be minted or written.
pub fn mint_domain_key(
    config_path: &Path,
    name: &str,
    selector: &str,
) -> Result<MintedKey, String> {
    let pair = crate::shared::dkim::generate_dkim_keypair()
        .map_err(|e| format!("couldn't mint a key: {e}"))?;

    // Keys live next to the config, so the config travels with them.
    let keydir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("keys");
    let _ = std::fs::create_dir_all(&keydir);
    let keyfile = keydir.join(format!("{name}.pem"));
    std::fs::write(&keyfile, &pair.private_key_pem)
        .map_err(|e| format!("couldn't write the key file {}: {e}", keyfile.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600));
    }

    Ok(MintedKey {
        rel_key: format!("keys/{name}.pem"),
        selector: selector.to_string(),
        dns_record_value: pair.dns_record_value,
    })
}
