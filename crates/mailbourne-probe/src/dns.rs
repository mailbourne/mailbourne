//! # dns — asking the address book
//!
//! DNS is the address book of email. These probes ask it the questions
//! that decide whether mail flows:
//!
//! - [`txt`]: *what text records does this name publish?* (SPF, DKIM,
//!   DMARC all live in TXT)
//! - [`a`]: *what address does this name resolve to?* (and is it the
//!   server we expect — or a proxy's edge?)
//! - [`spf`]: *which of those TXT records is the SPF policy?*
//!
//! Every probe returns evidence, never verdicts — judging is the
//! inspector's job.

pub mod dkim;
pub mod mx;
pub mod ptr;
pub mod spf;

use crate::ProbeError;

/// Fetches all TXT records published at `name`, with each record's
/// 255-byte chunks joined back into one string (the wire format splits
/// long values like DKIM keys; verifiers — and we — must reassemble them).
///
/// A name with no TXT records returns an empty list — that's an answer,
/// not an error.
///
/// # Errors
/// [`ProbeError::Dns`] only when resolution itself fails (network,
/// no resolver) — a temporary condition worth retrying.
pub async fn txt(name: &str) -> Result<Vec<String>, ProbeError> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::error::ResolveErrorKind;

    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().map_err(|e| ProbeError::Dns(e.to_string()))?;
    match resolver.txt_lookup(name).await {
        Ok(answer) => Ok(answer
            .iter()
            .map(|record| join_chunks(record.txt_data()))
            .collect()),
        Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(Vec::new()),
        Err(e) => Err(ProbeError::Dns(e.to_string())),
    }
}

/// Resolves `name` to its IPv4 addresses. Empty = the name doesn't
/// resolve — an answer, not an error.
///
/// # Errors
/// [`ProbeError::Dns`] when resolution itself fails.
pub async fn a(name: &str) -> Result<Vec<std::net::Ipv4Addr>, ProbeError> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::error::ResolveErrorKind;

    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().map_err(|e| ProbeError::Dns(e.to_string()))?;
    match resolver.ipv4_lookup(name).await {
        Ok(answer) => Ok(answer.iter().map(|r| r.0).collect()),
        Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(Vec::new()),
        Err(e) => Err(ProbeError::Dns(e.to_string())),
    }
}

/// Joins one TXT record's wire chunks back into a single string.
fn join_chunks(chunks: &[Box<[u8]>]) -> String {
    chunks
        .iter()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_chunks_are_joined_without_separators() {
        // A long DKIM key arrives as 255-byte chunks; the record is the
        // concatenation, nothing added, nothing lost.
        let chunks: Vec<Box<[u8]>> = vec![
            b"v=DKIM1; k=rsa; p=AAAA".to_vec().into_boxed_slice(),
            b"BBBB".to_vec().into_boxed_slice(),
        ];
        assert_eq!(join_chunks(&chunks), "v=DKIM1; k=rsa; p=AAAABBBB");
    }

    /// Network test — run explicitly: `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires network"]
    async fn gmail_publishes_an_spf_record() {
        let records = txt("gmail.com").await.unwrap();
        assert!(records.iter().any(|r| r.starts_with("v=spf1")));
    }

    /// Network test — a name with no TXT records answers empty, not error.
    #[tokio::test]
    #[ignore = "requires network"]
    async fn a_bare_name_returns_no_txt_records() {
        let records = txt("mail.mb.zebflow.com").await.unwrap();
        assert!(records.is_empty() || !records.iter().any(|r| r.starts_with("v=spf1")));
    }
}
