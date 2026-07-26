//! # edit — format-preserving config changes
//!
//! Mutating `mailbourne.toml` without destroying the comments or layout the
//! operator wrote by hand. serde (via [`Config::load`](crate::shared::core::config::Config::load))
//! reads; `toml_edit` writes — it keeps every blank line, comment, and key
//! order in place. Each function takes the TOML *text* and returns the
//! edited text, so the rules are pure and testable; the caller owns the
//! file I/O.

use crate::shared::core::config::Mode;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Out => "out",
        Mode::In => "in",
        Mode::Both => "both",
    }
}

fn parse(toml: &str) -> Result<DocumentMut, EditError> {
    toml.parse::<DocumentMut>()
        .map_err(|e| EditError::Parse(e.to_string()))
}

/// Finds the mutable `[[domain]]` table whose `name` matches.
fn domain_table_mut<'a>(doc: &'a mut DocumentMut, name: &str) -> Option<&'a mut Table> {
    doc.get_mut("domain")?
        .as_array_of_tables_mut()?
        .iter_mut()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
}

/// Why an edit couldn't be applied.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The existing file isn't valid TOML.
    #[error("the config isn't valid TOML: {0}")]
    Parse(String),
    /// Nothing in the config matches (a domain, account, or forward).
    #[error("not in the config: {0}")]
    NotFound(String),
    /// An entry with that identity already exists (a domain, account, or
    /// forward).
    #[error("already in the config: {0}")]
    Duplicate(String),
}

/// Appends an `[[account]]` block, preserving the rest of the file.
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML, [`EditError::Duplicate`]
/// if an account with `address` already exists.
pub fn add_account(
    toml: &str,
    address: &str,
    password_hash: &str,
    quota_bytes: u64,
) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    if account_exists(&doc, address) {
        return Err(EditError::Duplicate(address.to_string()));
    }
    let array = doc
        .as_table_mut()
        .entry("account")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| EditError::Parse("`account` is not an array of tables".to_string()))?;

    let mut table = Table::new();
    table["address"] = value(address);
    table["password_hash"] = value(password_hash);
    if quota_bytes > 0 {
        table["quota_bytes"] = value(quota_bytes as i64);
    }
    array.push(table);
    Ok(doc.to_string())
}

/// Whether an `[[account]]` with `address` is already present.
fn account_exists(doc: &DocumentMut, address: &str) -> bool {
    doc.get("account")
        .and_then(|item| item.as_array_of_tables())
        .is_some_and(|arr| {
            arr.iter()
                .any(|t| t.get("address").and_then(|v| v.as_str()) == Some(address))
        })
}

/// Sets a domain's mode, preserving everything else in the file.
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML, [`EditError::NotFound`]
/// if no domain matches `name`.
pub fn set_domain_mode(toml: &str, name: &str, mode: Mode) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    let table =
        domain_table_mut(&mut doc, name).ok_or_else(|| EditError::NotFound(name.to_string()))?;
    table["mode"] = value(mode_str(mode));
    Ok(doc.to_string())
}

/// Points a domain at a new DKIM selector + key path (rotation).
///
/// # Errors
/// See [`set_domain_mode`].
pub fn set_domain_dkim(
    toml: &str,
    name: &str,
    selector: &str,
    key_path: &str,
) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    let table =
        domain_table_mut(&mut doc, name).ok_or_else(|| EditError::NotFound(name.to_string()))?;
    table["dkim_selector"] = value(selector);
    table["dkim_key"] = value(key_path);
    Ok(doc.to_string())
}

/// Removes a domain's `[[domain]]` block entirely.
///
/// # Errors
/// See [`set_domain_mode`].
pub fn remove_domain(toml: &str, name: &str) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    let array = doc
        .get_mut("domain")
        .and_then(|item| item.as_array_of_tables_mut())
        .ok_or_else(|| EditError::NotFound(name.to_string()))?;
    let before = array.len();
    array.retain(|t| t.get("name").and_then(|v| v.as_str()) != Some(name));
    if array.len() == before {
        return Err(EditError::NotFound(name.to_string()));
    }
    Ok(doc.to_string())
}

/// Appends a `[[domain]]` block for a brand-new domain, preserving the file.
///
/// The single source of truth for registering a domain — both the CLI
/// (`mailbourne domain add`) and the interactive console go through here.
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML, [`EditError::Duplicate`]
/// if a domain with `name` already exists.
pub fn add_domain(
    toml: &str,
    name: &str,
    mode: Mode,
    selector: &str,
    key_path: &str,
) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    if domain_table_mut(&mut doc, name).is_some() {
        return Err(EditError::Duplicate(name.to_string()));
    }
    let array = doc
        .as_table_mut()
        .entry("domain")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| EditError::Parse("`domain` is not an array of tables".to_string()))?;

    let mut table = Table::new();
    table["name"] = value(name);
    table["mode"] = value(mode_str(mode));
    table["dkim_selector"] = value(selector);
    table["dkim_key"] = value(key_path);
    array.push(table);
    Ok(doc.to_string())
}

/// Removes the `[[account]]` block for `address`.
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML, [`EditError::NotFound`]
/// if no account matches.
pub fn remove_account(toml: &str, address: &str) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    let array = doc
        .get_mut("account")
        .and_then(|item| item.as_array_of_tables_mut())
        .ok_or_else(|| EditError::NotFound(address.to_string()))?;
    let before = array.len();
    array.retain(|t| t.get("address").and_then(|v| v.as_str()) != Some(address));
    if array.len() == before {
        return Err(EditError::NotFound(address.to_string()));
    }
    Ok(doc.to_string())
}

/// Replaces an account's password hash (a password change), leaving its
/// quota and enabled flag alone.
///
/// # Errors
/// See [`remove_account`].
pub fn set_account_password(
    toml: &str,
    address: &str,
    password_hash: &str,
) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    let table = doc
        .get_mut("account")
        .and_then(|item| item.as_array_of_tables_mut())
        .and_then(|arr| {
            arr.iter_mut()
                .find(|t| t.get("address").and_then(|v| v.as_str()) == Some(address))
        })
        .ok_or_else(|| EditError::NotFound(address.to_string()))?;
    table["password_hash"] = value(password_hash);
    Ok(doc.to_string())
}

/// The `[server]` table, which every valid config has.
fn server_table_mut(doc: &mut DocumentMut) -> Result<&mut Table, EditError> {
    doc.get_mut("server")
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| EditError::Parse("no [server] table".to_string()))
}

/// Sets a boolean field under `[server]` (e.g. `dmarc_enforce`).
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML or has no `[server]`.
pub fn set_server_bool(toml: &str, key: &str, val: bool) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    server_table_mut(&mut doc)?[key] = value(val);
    Ok(doc.to_string())
}

/// Sets an integer field under `[server]` (e.g. `mailbox_quota_bytes`).
///
/// # Errors
/// See [`set_server_bool`].
pub fn set_server_int(toml: &str, key: &str, val: i64) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    server_table_mut(&mut doc)?[key] = value(val);
    Ok(doc.to_string())
}

/// Sets a string field under `[server]` (e.g. `webhook_url`, `tls_cert`).
///
/// # Errors
/// See [`set_server_bool`].
pub fn set_server_string(toml: &str, key: &str, val: &str) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    server_table_mut(&mut doc)?[key] = value(val);
    Ok(doc.to_string())
}

/// Removes an optional field under `[server]` (e.g. unset `webhook_url`).
/// Clearing an absent key is a no-op, not an error.
///
/// # Errors
/// See [`set_server_bool`].
pub fn clear_server_field(toml: &str, key: &str) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    server_table_mut(&mut doc)?.remove(key);
    Ok(doc.to_string())
}

/// Appends a `[[forward]]` rule relaying `match_recipient` on to `to`.
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML, [`EditError::Duplicate`]
/// if a rule for `match_recipient` already exists.
pub fn add_forward(toml: &str, match_recipient: &str, to: &str) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    if forward_exists(&doc, match_recipient) {
        return Err(EditError::Duplicate(match_recipient.to_string()));
    }
    let array = doc
        .as_table_mut()
        .entry("forward")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| EditError::Parse("`forward` is not an array of tables".to_string()))?;

    let mut table = Table::new();
    table["match"] = value(match_recipient);
    table["to"] = value(to);
    array.push(table);
    Ok(doc.to_string())
}

/// Whether a `[[forward]]` rule for `match_recipient` is already present.
fn forward_exists(doc: &DocumentMut, match_recipient: &str) -> bool {
    doc.get("forward")
        .and_then(|item| item.as_array_of_tables())
        .is_some_and(|arr| {
            arr.iter()
                .any(|t| t.get("match").and_then(|v| v.as_str()) == Some(match_recipient))
        })
}

/// Removes the `[[forward]]` rule matching `match_recipient`.
///
/// # Errors
/// [`EditError::Parse`] if the text isn't valid TOML, [`EditError::NotFound`]
/// if no rule matches.
pub fn remove_forward(toml: &str, match_recipient: &str) -> Result<String, EditError> {
    let mut doc = parse(toml)?;
    let array = doc
        .get_mut("forward")
        .and_then(|item| item.as_array_of_tables_mut())
        .ok_or_else(|| EditError::NotFound(match_recipient.to_string()))?;
    let before = array.len();
    array.retain(|t| t.get("match").and_then(|v| v.as_str()) != Some(match_recipient));
    if array.len() == before {
        return Err(EditError::NotFound(match_recipient.to_string()));
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::core::config::Config;

    const SAMPLE: &str = r#"# my server
[server]
hostname = "mail.hq.example.com"

[[domain]]
name = "a.example.com"   # the first one
mode = "out"
dkim_selector = "s1"
dkim_key = "keys/a.pem"

[[domain]]
name = "b.example.com"
mode = "both"
"#;

    #[test]
    fn set_mode_changes_only_that_domain_and_keeps_comments() {
        let out = set_domain_mode(SAMPLE, "a.example.com", Mode::Both).unwrap();
        assert!(out.contains("# my server"), "top comment lost");
        assert!(out.contains("# the first one"), "inline comment lost");
        let cfg = Config::parse_toml(&out).unwrap();
        assert_eq!(cfg.domain("a.example.com").unwrap().mode, Mode::Both);
        assert_eq!(cfg.domain("b.example.com").unwrap().mode, Mode::Both);
    }

    #[test]
    fn remove_takes_out_one_block_leaves_the_rest() {
        let out = remove_domain(SAMPLE, "a.example.com").unwrap();
        let cfg = Config::parse_toml(&out).unwrap();
        assert!(cfg.domain("a.example.com").is_none());
        assert!(cfg.domain("b.example.com").is_some());
        assert!(out.contains("# my server"), "top comment lost");
    }

    #[test]
    fn set_dkim_updates_selector_and_key() {
        let out = set_domain_dkim(SAMPLE, "a.example.com", "s2", "keys/a-2.pem").unwrap();
        let cfg = Config::parse_toml(&out).unwrap();
        let d = cfg.domain("a.example.com").unwrap();
        assert_eq!(d.dkim_selector.as_deref(), Some("s2"));
        assert_eq!(
            d.dkim_key.as_deref(),
            Some(std::path::Path::new("keys/a-2.pem"))
        );
    }

    #[test]
    fn add_account_appends_and_refuses_duplicates() {
        let out = add_account(SAMPLE, "bob@a.example.com", "$argon2id$abc", 2048).unwrap();
        assert!(out.contains("# my server"), "top comment lost");
        let cfg = Config::parse_toml(&out).unwrap();
        let acct = cfg
            .accounts
            .iter()
            .find(|a| a.address == "bob@a.example.com")
            .expect("account added");
        assert_eq!(acct.password_hash, "$argon2id$abc");
        assert_eq!(acct.quota_bytes, 2048);
        assert!(acct.enabled, "enabled defaults true");
        // Adding the same address again is refused.
        assert!(matches!(
            add_account(&out, "bob@a.example.com", "x", 0),
            Err(EditError::Duplicate(_))
        ));
    }

    #[test]
    fn editing_a_missing_domain_is_not_found() {
        assert!(matches!(
            set_domain_mode(SAMPLE, "nope.example.com", Mode::Out),
            Err(EditError::NotFound(_))
        ));
        assert!(matches!(
            remove_domain(SAMPLE, "nope.example.com"),
            Err(EditError::NotFound(_))
        ));
    }

    /// A sample that already has an account and a forward, for the mutations
    /// that touch them.
    const WITH_PEOPLE: &str = r#"# hq
[server]
hostname = "mail.hq.example.com"
dmarc_enforce = true

[[domain]]
name = "a.example.com"
mode = "both"

[[account]]
address = "bob@a.example.com"
password_hash = "$argon2id$old"
quota_bytes = 1024

[[forward]]
match = "team@a.example.com"
to = "bob@gmail.com"
"#;

    #[test]
    fn add_domain_appends_a_block_and_refuses_duplicates() {
        let out = add_domain(SAMPLE, "c.example.com", Mode::Out, "mb2026", "keys/c.pem").unwrap();
        assert!(out.contains("# my server"), "top comment lost");
        assert!(out.contains("# the first one"), "inline comment lost");
        let cfg = Config::parse_toml(&out).unwrap();
        let d = cfg.domain("c.example.com").expect("domain added");
        assert_eq!(d.mode, Mode::Out);
        assert_eq!(d.dkim_selector.as_deref(), Some("mb2026"));
        assert_eq!(
            d.dkim_key.as_deref(),
            Some(std::path::Path::new("keys/c.pem"))
        );
        // The existing domains are untouched.
        assert!(cfg.domain("a.example.com").is_some());
        assert!(cfg.domain("b.example.com").is_some());
        // Adding the same name again is refused.
        assert!(matches!(
            add_domain(&out, "c.example.com", Mode::Both, "s", "k"),
            Err(EditError::Duplicate(_))
        ));
    }

    #[test]
    fn remove_account_takes_out_one_leaves_the_rest() {
        let out = remove_account(WITH_PEOPLE, "bob@a.example.com").unwrap();
        assert!(out.contains("# hq"), "top comment lost");
        let cfg = Config::parse_toml(&out).unwrap();
        assert!(
            cfg.accounts
                .iter()
                .all(|a| a.address != "bob@a.example.com")
        );
        // Removing someone who isn't there is NotFound.
        assert!(matches!(
            remove_account(WITH_PEOPLE, "ghost@a.example.com"),
            Err(EditError::NotFound(_))
        ));
    }

    #[test]
    fn set_account_password_swaps_only_the_hash() {
        let out = set_account_password(WITH_PEOPLE, "bob@a.example.com", "$argon2id$new").unwrap();
        let cfg = Config::parse_toml(&out).unwrap();
        let bob = cfg
            .accounts
            .iter()
            .find(|a| a.address == "bob@a.example.com")
            .unwrap();
        assert_eq!(bob.password_hash, "$argon2id$new");
        assert_eq!(bob.quota_bytes, 1024, "quota untouched");
        assert!(matches!(
            set_account_password(WITH_PEOPLE, "ghost@a.example.com", "x"),
            Err(EditError::NotFound(_))
        ));
    }

    #[test]
    fn server_setters_change_values_and_keep_comments() {
        let out = set_server_bool(WITH_PEOPLE, "dmarc_enforce", false).unwrap();
        let out = set_server_int(&out, "mailbox_quota_bytes", 2048).unwrap();
        let out = set_server_string(&out, "webhook_url", "https://hook.example/x").unwrap();
        assert!(out.contains("# hq"), "top comment lost");
        let cfg = Config::parse_toml(&out).unwrap();
        assert!(!cfg.server.dmarc_enforce);
        assert_eq!(cfg.server.mailbox_quota_bytes, 2048);
        assert_eq!(
            cfg.server.webhook_url.as_deref(),
            Some("https://hook.example/x")
        );
    }

    #[test]
    fn clear_server_field_removes_an_optional_key() {
        let with = set_server_string(WITH_PEOPLE, "webhook_url", "https://hook.example/x").unwrap();
        let out = clear_server_field(&with, "webhook_url").unwrap();
        let cfg = Config::parse_toml(&out).unwrap();
        assert!(cfg.server.webhook_url.is_none());
        // Clearing an absent key is a no-op, not an error.
        assert!(clear_server_field(&out, "webhook_url").is_ok());
    }

    #[test]
    fn add_and_remove_forward() {
        let out = add_forward(WITH_PEOPLE, "sales@a.example.com", "sue@gmail.com").unwrap();
        let cfg = Config::parse_toml(&out).unwrap();
        assert!(
            cfg.forwards
                .iter()
                .any(|f| f.match_recipient == "sales@a.example.com" && f.to == "sue@gmail.com")
        );
        // Duplicate match is refused.
        assert!(matches!(
            add_forward(&out, "sales@a.example.com", "elsewhere@gmail.com"),
            Err(EditError::Duplicate(_))
        ));
        // Remove it again.
        let gone = remove_forward(&out, "sales@a.example.com").unwrap();
        let cfg = Config::parse_toml(&gone).unwrap();
        assert!(
            cfg.forwards
                .iter()
                .all(|f| f.match_recipient != "sales@a.example.com")
        );
        assert!(matches!(
            remove_forward(WITH_PEOPLE, "ghost@a.example.com"),
            Err(EditError::NotFound(_))
        ));
    }
}
