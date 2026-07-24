//! # edit — format-preserving config changes
//!
//! Mutating `mailbourne.toml` without destroying the comments or layout the
//! operator wrote by hand. serde (via [`Config::load`](crate::config::Config::load))
//! reads; `toml_edit` writes — it keeps every blank line, comment, and key
//! order in place. Each function takes the TOML *text* and returns the
//! edited text, so the rules are pure and testable; the caller owns the
//! file I/O.

use crate::config::Mode;
use toml_edit::{DocumentMut, Table, value};

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
    /// No `[[domain]]` block has that name.
    #[error("no domain named {0} in the config")]
    NotFound(String),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

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
}
