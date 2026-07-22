//! # spf — who is allowed to send for this domain?
//!
//! SPF is the guest list: a TXT record (`v=spf1 …`) naming the IPs allowed
//! to send mail *from this domain's envelope sender*. Receivers check the
//! connecting IP against it. Crucially, SPF judges the **envelope**
//! `MAIL FROM` — not the `From:` header your mail client shows. Aligning
//! those two is DMARC's job.
//!
//! One cruel rule this module exists to enforce: **a domain may publish at
//! most ONE SPF record.** Two `v=spf1` records = permanent SPF failure
//! (permerror) — the classic broken-by-adding-a-provider mistake.

/// Picks the SPF records out of a domain's TXT set.
///
/// Zero is an answer (no policy), one is healthy, and two or more is the
/// permerror trap — the caller must treat that as broken, not pick one.
pub fn find_spf(txt_records: &[String]) -> Vec<&String> {
    txt_records
        .iter()
        .filter(|r| r.trim_start().to_lowercase().starts_with("v=spf1"))
        .collect()
}

/// Does this SPF record authorize the given IPv4 address explicitly?
pub fn authorizes_ip(spf: &str, ip: std::net::Ipv4Addr) -> bool {
    spf.split_whitespace()
        .any(|mechanism| mechanism.eq_ignore_ascii_case(&format!("ip4:{ip}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_records_are_found_among_other_txt() {
        let records = vec![
            "google-site-verification=abc".to_string(),
            "v=spf1 ip4:1.2.3.4 -all".to_string(),
        ];
        let found = find_spf(&records);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("ip4:1.2.3.4"));
    }

    #[test]
    fn two_spf_records_are_both_reported_for_the_permerror_verdict() {
        let records = vec![
            "v=spf1 ip4:1.2.3.4 -all".to_string(),
            "v=spf1 include:other.example ~all".to_string(),
        ];
        assert_eq!(find_spf(&records).len(), 2);
    }

    #[test]
    fn ip_authorization_is_detected_exactly() {
        let spf = "v=spf1 ip4:109.123.247.215 include:_spf.example.net -all";
        assert!(authorizes_ip(spf, "109.123.247.215".parse().unwrap()));
        assert!(!authorizes_ip(spf, "1.2.3.4".parse().unwrap()));
    }
}
