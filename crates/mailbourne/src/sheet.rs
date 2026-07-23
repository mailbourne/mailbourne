//! # sheet — what to paste, and the truth about what's there
//!
//! The artifact sheet for one domain: every DNS record it needs, at
//! copy-paste fidelity, judged against what's *already published* — so
//! the sheet never tells you to add a second SPF record (permerror!),
//! never re-prints a record that's already right, and never silently
//! truncates a value.
//!
//! Pure logic: probes gather the evidence elsewhere; this module only
//! reasons about it. That's what makes every rule below testable offline.

use mailbourne_core::config::Mode;

/// What to do about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowStatus {
    /// Not published yet — paste it.
    Add,
    /// Published and correct — nothing to do.
    AlreadyCorrect,
    /// Published but wrong — replace it with the printed value
    /// (`current` shows what's there now, so the change is auditable).
    Replace {
        /// What DNS currently serves.
        current: String,
    },
    /// Actively broken in a way that needs a human decision first.
    Broken {
        /// Plain-language description of the breakage.
        why: String,
    },
}

/// One row of the sheet: a record at copy-paste fidelity.
#[derive(Debug, Clone)]
pub struct RecordRow {
    /// Fully-qualified record name (`mb2026._domainkey.ds.example.com`).
    pub host: String,
    /// Record type (`TXT`, `MX`, `A`).
    pub rtype: &'static str,
    /// The full value to paste — never truncated.
    pub value: String,
    /// The verdict for this row.
    pub status: RowStatus,
}

/// The whole sheet: rows plus the friendly notes around them.
#[derive(Debug, Clone)]
pub struct Sheet {
    /// The records, in paste order.
    pub rows: Vec<RecordRow>,
    /// Context lines (mode explanations, permerror warnings, next steps).
    pub notes: Vec<String>,
}

/// Everything the sheet needs to know — evidence in, judgement out.
#[derive(Debug, Default)]
pub struct Evidence {
    /// The domain's published TXT records (SPF lives here).
    pub domain_txt: Vec<String>,
    /// TXT at `<selector>._domainkey.<domain>`.
    pub dkim_txt: Vec<String>,
    /// TXT at `_dmarc.<domain>`.
    pub dmarc_txt: Vec<String>,
    /// The server's outbound IPv4, when known (from the mail host's A).
    pub server_ip: Option<std::net::Ipv4Addr>,
    /// The DKIM record derived from the key on disk, when a key exists.
    pub dkim_record_from_key: Option<String>,
}

/// Builds the artifact sheet for one domain.
pub fn build(
    domain: &str,
    mode: Mode,
    selector: Option<&str>,
    server_hostname: &str,
    evidence: &Evidence,
) -> Sheet {
    let mut rows = Vec::new();
    let mut notes = Vec::new();

    // ── SPF: the one-record rule governs everything ──────────────────
    let spf_found: Vec<&String> = evidence
        .domain_txt
        .iter()
        .filter(|r| r.trim_start().to_lowercase().starts_with("v=spf1"))
        .collect();
    match (spf_found.as_slice(), evidence.server_ip) {
        ([], Some(ip)) => rows.push(RecordRow {
            host: domain.to_string(),
            rtype: "TXT",
            value: format!("v=spf1 ip4:{ip} -all"),
            status: RowStatus::Add,
        }),
        ([], None) => {
            rows.push(RecordRow {
                host: domain.to_string(),
                rtype: "TXT",
                value: "v=spf1 ip4:<server-ip> -all".to_string(),
                status: RowStatus::Add,
            });
            notes.push(format!(
                "couldn't resolve {server_hostname} to an IP yet — publish its A \
                 record first, then the SPF value above gets a real address"
            ));
        }
        ([one], Some(ip)) => {
            let authorizes = one
                .split_whitespace()
                .any(|m| m.eq_ignore_ascii_case(&format!("ip4:{ip}")));
            if authorizes {
                rows.push(RecordRow {
                    host: domain.to_string(),
                    rtype: "TXT",
                    value: (*one).clone(),
                    status: RowStatus::AlreadyCorrect,
                });
            } else {
                rows.push(RecordRow {
                    host: domain.to_string(),
                    rtype: "TXT",
                    value: merge_spf(one, ip),
                    status: RowStatus::Replace {
                        current: (*one).clone(),
                    },
                });
                notes.push(
                    "an SPF record already exists (another provider?) — REPLACE it \
                     with the merged value above; a domain may only have ONE"
                        .to_string(),
                );
            }
        }
        (many, _) if many.len() > 1 => {
            rows.push(RecordRow {
                host: domain.to_string(),
                rtype: "TXT",
                value: String::new(),
                status: RowStatus::Broken {
                    why: format!("{} SPF records published at once", many.len()),
                },
            });
            notes.push(format!(
                "heads-up: {domain} publishes {} SPF records — receivers treat that \
                 as permerror (SPF permanently failing). keep exactly ONE record; \
                 merge the mechanisms by hand, then re-run this sheet",
                many.len()
            ));
        }
        _ => {}
    }

    // ── DKIM: the key on disk vs the record in the sky ────────────────
    if let Some(selector) = selector {
        let host = format!("{selector}._domainkey.{domain}");
        let published = evidence
            .dkim_txt
            .iter()
            .find(|r| r.trim_start().to_lowercase().starts_with("v=dkim1"));
        match (&evidence.dkim_record_from_key, published) {
            (Some(expected), Some(actual)) if normalized(actual) == normalized(expected) => {
                rows.push(RecordRow {
                    host,
                    rtype: "TXT",
                    value: expected.clone(),
                    status: RowStatus::AlreadyCorrect,
                });
            }
            (Some(expected), Some(actual)) => {
                rows.push(RecordRow {
                    host,
                    rtype: "TXT",
                    value: expected.clone(),
                    status: RowStatus::Replace {
                        current: actual.clone(),
                    },
                });
                notes.push(
                    "the DKIM key on disk doesn't match what DNS serves — the classic \
                     silent failure (re-created key?). replace the record with the \
                     value above, or mail keeps signing with a seal nobody can verify"
                        .to_string(),
                );
            }
            (Some(expected), None) => rows.push(RecordRow {
                host,
                rtype: "TXT",
                value: expected.clone(),
                status: RowStatus::Add,
            }),
            (None, _) => {
                rows.push(RecordRow {
                    host,
                    rtype: "TXT",
                    value: String::new(),
                    status: RowStatus::Broken {
                        why: "no DKIM key on disk — this domain can't sign yet".to_string(),
                    },
                });
                notes.push(format!(
                    "mint the key with: mailbourne domain keygen {domain} — then this \
                     row becomes a paste-ready record"
                ));
            }
        }
    }

    // ── DMARC ─────────────────────────────────────────────────────────
    let dmarc_host = format!("_dmarc.{domain}");
    match evidence
        .dmarc_txt
        .iter()
        .find(|r| r.trim_start().to_lowercase().starts_with("v=dmarc1"))
    {
        Some(existing) => rows.push(RecordRow {
            host: dmarc_host,
            rtype: "TXT",
            value: existing.clone(),
            status: RowStatus::AlreadyCorrect,
        }),
        None => rows.push(RecordRow {
            host: dmarc_host,
            rtype: "TXT",
            value: format!("v=DMARC1; p=none; rua=mailto:postmaster@{domain}"),
            status: RowStatus::Add,
        }),
    }

    // ── MX: mode decides, and out-mode says so out loud ──────────────
    match mode {
        Mode::Out => notes.push(format!(
            "MX: leaving it alone — {domain} is registered \"out\" (send-only), so \
             inbound stays with your current provider. that's the point of the mode"
        )),
        Mode::In | Mode::Both => rows.push(RecordRow {
            host: domain.to_string(),
            rtype: "MX",
            value: format!("10 {server_hostname}."),
            status: RowStatus::Add,
        }),
    }

    Sheet { rows, notes }
}

/// Whitespace-insensitive comparison for DNS values (providers re-chunk
/// and re-space long records without changing their meaning).
fn normalized(record: &str) -> String {
    record.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Merges our server's IP into an existing SPF record — inserted before
/// the terminal `all` mechanism, everything else preserved.
///
/// This is the answer to email's cruelest gotcha: a domain may publish at
/// most ONE SPF record, so joining an existing provider means *merging*,
/// never adding a second record.
pub fn merge_spf(existing: &str, ip: std::net::Ipv4Addr) -> String {
    let mechanism = format!("ip4:{ip}");
    let tokens: Vec<&str> = existing.split_whitespace().collect();

    // The `all` terminal ends every SPF evaluation — our mechanism must
    // land before it or it never gets read.
    if let Some(all_at) = tokens.iter().position(|t| {
        t.trim_start_matches(['+', '-', '~', '?'])
            .eq_ignore_ascii_case("all")
    }) {
        let mut merged = tokens[..all_at].to_vec();
        merged.push(&mechanism);
        merged.extend_from_slice(&tokens[all_at..]);
        merged.join(" ")
    } else {
        format!("{existing} {mechanism}")
    }
}

/// A rendered sheet ready to print, plus how many rows still need action.
pub struct Rendered {
    /// The formatted block.
    pub text: String,
    /// How many rows still need the user to do something.
    pub to_do: usize,
}

/// Renders a sheet as the human-facing block — shared by `domain show` and
/// the console, so both speak with one voice.
pub fn render(
    sheet: &Sheet,
    domain: &str,
    server_hostname: &str,
    server_ip: Option<std::net::Ipv4Addr>,
) -> Rendered {
    use std::fmt::Write;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "── {domain} · server {server_hostname}{} ──\n",
        match server_ip {
            Some(ip) => format!(" ({ip})"),
            None => " (does not resolve yet!)".to_string(),
        }
    );
    let mut to_do = 0;
    for row in &sheet.rows {
        let (glyph, verb) = match &row.status {
            RowStatus::Add => {
                to_do += 1;
                ("+", "ADD")
            }
            RowStatus::AlreadyCorrect => ("✓", "already sorted"),
            RowStatus::Replace { .. } => {
                to_do += 1;
                ("↻", "REPLACE")
            }
            RowStatus::Broken { .. } => {
                to_do += 1;
                ("✗", "NEEDS A DECISION")
            }
        };
        let _ = writeln!(text, "  {glyph} [{verb}]  {}  {}", row.rtype, row.host);
        if let RowStatus::Broken { why } = &row.status {
            let _ = writeln!(text, "      {why}");
        } else if !row.value.is_empty() {
            let _ = writeln!(text, "      {}", row.value);
        }
        if let RowStatus::Replace { current } = &row.status {
            let _ = writeln!(text, "      (currently: {current})");
        }
        let _ = writeln!(text);
    }
    for note in &sheet.notes {
        let _ = writeln!(text, "  · {note}");
    }
    Rendered { text, to_do }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: &str = "109.123.247.215";

    fn ip() -> std::net::Ipv4Addr {
        IP.parse().unwrap()
    }

    fn spf_row(sheet: &Sheet) -> &RecordRow {
        sheet
            .rows
            .iter()
            .find(|r| {
                r.value.starts_with("v=spf1") || matches!(&r.status, RowStatus::Broken { .. })
            })
            .expect("sheet always has an SPF row")
    }

    #[test]
    fn render_counts_action_rows_and_shows_full_values() {
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        let r = render(&sheet, "ds.example.com", "mail.hq.example.com", Some(ip()));
        // SPF add + DMARC add + DKIM missing = 3 things to do.
        assert!(r.to_do >= 2, "expected action rows, got {}", r.to_do);
        assert!(
            r.text.contains(&format!("ip4:{IP}")),
            "values must not be truncated"
        );
    }

    #[test]
    fn merging_inserts_the_ip_before_the_all_terminal() {
        let merged = merge_spf("v=spf1 include:_spf.mx.cloudflare.net ~all", ip());
        assert_eq!(
            merged,
            format!("v=spf1 include:_spf.mx.cloudflare.net ip4:{IP} ~all")
        );
    }

    #[test]
    fn merging_without_an_all_terminal_appends() {
        let merged = merge_spf("v=spf1 mx", ip());
        assert_eq!(merged, format!("v=spf1 mx ip4:{IP}"));
    }

    #[test]
    fn no_spf_at_all_means_a_fresh_add() {
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        let row = spf_row(&sheet);
        assert_eq!(row.status, RowStatus::Add);
        assert_eq!(row.value, format!("v=spf1 ip4:{IP} -all"));
    }

    #[test]
    fn an_spf_already_naming_our_ip_is_already_correct() {
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                domain_txt: vec![format!("v=spf1 ip4:{IP} -all")],
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        assert_eq!(spf_row(&sheet).status, RowStatus::AlreadyCorrect);
    }

    #[test]
    fn an_existing_foreign_spf_becomes_a_merge_replacement() {
        // The user's own real-world case: Cloudflare Email Routing already
        // publishes SPF — we must merge, never add a second record.
        let existing = "v=spf1 include:_spf.mx.cloudflare.net ~all";
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                domain_txt: vec![existing.to_string()],
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        match &spf_row(&sheet).status {
            RowStatus::Replace { current } => assert_eq!(current, existing),
            other => panic!("expected Replace, got {other:?}"),
        }
        assert!(
            spf_row(&sheet)
                .value
                .contains("include:_spf.mx.cloudflare.net")
        );
        assert!(spf_row(&sheet).value.contains(&format!("ip4:{IP}")));
    }

    #[test]
    fn two_spf_records_are_the_permerror_trap() {
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                domain_txt: vec![
                    "v=spf1 ip4:1.2.3.4 -all".to_string(),
                    "v=spf1 include:x.example ~all".to_string(),
                ],
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        assert!(matches!(spf_row(&sheet).status, RowStatus::Broken { .. }));
        assert!(
            sheet.notes.iter().any(|n| n.contains("permerror")),
            "the permerror trap deserves a plain-language note: {:?}",
            sheet.notes
        );
    }

    #[test]
    fn a_key_mismatch_is_the_classic_silent_failure() {
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                dkim_txt: vec!["v=DKIM1; k=rsa; p=OLDKEY".to_string()],
                dkim_record_from_key: Some("v=DKIM1; k=rsa; p=NEWKEY".to_string()),
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        let dkim = sheet
            .rows
            .iter()
            .find(|r| r.host.starts_with("s1._domainkey"))
            .unwrap();
        assert!(matches!(&dkim.status, RowStatus::Replace { .. }));
    }

    #[test]
    fn a_missing_key_is_a_visible_gap_not_a_footnote() {
        // "all sorted" while the key is missing would be a green-checkmark
        // lie — the gap must be a row the summary counts.
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                server_ip: Some(ip()),
                dkim_record_from_key: None,
                ..Default::default()
            },
        );
        let dkim = sheet
            .rows
            .iter()
            .find(|r| r.host.starts_with("s1._domainkey"))
            .expect("the gap must appear as a row");
        assert!(matches!(&dkim.status, RowStatus::Broken { .. }));
    }

    #[test]
    fn out_mode_says_leave_mx_alone() {
        let sheet = build(
            "ds.example.com",
            Mode::Out,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        assert!(!sheet.rows.iter().any(|r| r.rtype == "MX"));
        assert!(
            sheet.notes.iter().any(|n| n.contains("MX")),
            "out mode must SAY it's leaving MX alone: {:?}",
            sheet.notes
        );
    }

    #[test]
    fn both_mode_wants_an_mx_row() {
        let sheet = build(
            "mb.example.com",
            Mode::Both,
            Some("s1"),
            "mail.hq.example.com",
            &Evidence {
                server_ip: Some(ip()),
                ..Default::default()
            },
        );
        let mx = sheet.rows.iter().find(|r| r.rtype == "MX").unwrap();
        assert!(mx.value.contains("mail.hq.example.com"));
    }
}
