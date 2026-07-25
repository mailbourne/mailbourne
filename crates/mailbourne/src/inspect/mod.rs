//! # inspect — the built-in inspector
//!
//! Always compiled — checking whether the world will trust your mail is part
//! of what mailbourne *is*, not an optional add-on. Ask the world, judge the
//! evidence, render nothing:
//!
//! - [`probe`] — read-only questions: DNS, port dials, TLS, blocklists
//! - [`checklist`] — turn evidence into a WHAT/WHY/DO/VERIFY/LEARN report
//! - [`sheet`] — a judged, ready-to-render view of one domain's records
//!
//! The free function [`domain`] is the operation behind both `domain show`
//! (CLI) and the console's "check what's live": probe DNS for a domain's
//! records, compare against the key on disk and the server's facts, and hand
//! back a judged [`Sheet`]. One implementation, two callers — they can't drift.

pub mod checklist;
pub mod probe;
pub mod sheet;

use crate::inspect::sheet::{Evidence, Sheet};
use crate::shared::core::config::Config;

/// Gathers live DNS evidence for `name` and builds its judged sheet.
///
/// Returns `None` when the domain isn't in the registry. The
/// [`std::net::Ipv4Addr`] alongside the sheet is the server's resolved IP
/// (or `None` if the hostname doesn't resolve yet) — the console prints it
/// in the header.
pub async fn domain(config: &Config, name: &str) -> Option<(Sheet, Option<std::net::Ipv4Addr>)> {
    let domain = config.domain(name)?;
    let selector = domain.dkim_selector.clone();
    let dkim_host = selector
        .as_deref()
        .map(|s| format!("{s}._domainkey.{name}"));

    let domain_txt = crate::inspect::probe::dns::txt(name)
        .await
        .unwrap_or_default();
    let dkim_txt = match &dkim_host {
        Some(host) => crate::inspect::probe::dns::txt(host)
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let dmarc_txt = crate::inspect::probe::dns::txt(&format!("_dmarc.{name}"))
        .await
        .unwrap_or_default();
    let server_ip = crate::inspect::probe::dns::a(&config.server.hostname)
        .await
        .unwrap_or_default()
        .first()
        .copied();

    let dkim_record_from_key = domain
        .dkim_key
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|pem| crate::shared::dkim::public_record_for(&pem).ok());

    let evidence = Evidence {
        domain_txt,
        dkim_txt,
        dmarc_txt,
        server_ip,
        dkim_record_from_key,
    };
    let sheet = sheet::build(
        name,
        domain.mode,
        selector.as_deref(),
        &config.server.hostname,
        &evidence,
    );
    Some((sheet, server_ip))
}
