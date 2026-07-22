//! # 2 · route — find the door
//!
//! We know *who* the message is for (`bob@example.com`); DNS tells us
//! *where*: the domain's MX records, tried lowest-priority-number first,
//! falling back to the next host when one is unreachable. No MX at all
//! falls back to the domain's A record (RFC 5321 §5.1); null MX (`MX 0 .`)
//! means the domain refuses mail — bounce, don't retry.
//!
//! The decision itself ([`plan`]) is pure logic, separated from the DNS
//! lookup so it can be tested exhaustively without a network — and so the
//! inspector's R1 check can reuse it against probe evidence.

/// One MX candidate: a priority number and the host to dial.
///
/// Lower priority = try first. Equal priorities are legitimate (crude load
/// balancing); order between them is not significant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxHost {
    /// The preference number from DNS — lower wins.
    pub priority: u16,
    /// The hostname to connect to on port 25.
    pub host: String,
}

/// The routing decision for one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Dial these hosts in order until one accepts the connection.
    ToHosts(Vec<MxHost>),
    /// The domain publishes null MX (`MX 0 .`, RFC 7505): it refuses all
    /// mail, on purpose. Bounce immediately — retrying would be rude.
    RefusesMail,
}

/// Turns a domain's raw MX records into a delivery plan.
///
/// - Records are sorted lowest-priority-first (the order we must dial).
/// - **No MX records at all** falls back to the domain itself
///   (RFC 5321 §5.1 — "implicit MX").
/// - **Null MX** (a record whose host is `.` or empty) means the domain
///   deliberately refuses mail → [`Route::RefusesMail`].
pub fn plan(domain: &str, mx_records: Vec<MxHost>) -> Route {
    if mx_records.is_empty() {
        // Implicit MX: the domain itself, at top priority.
        return Route::ToHosts(vec![MxHost {
            priority: 0,
            host: domain.to_string(),
        }]);
    }

    let mut hosts: Vec<MxHost> = mx_records
        .into_iter()
        .map(|mut mx| {
            if let Some(stripped) = mx.host.strip_suffix('.') {
                mx.host = stripped.to_string();
            }
            mx
        })
        .collect();

    // Null MX: a lone "." (now normalized to "") is a deliberate refusal.
    if hosts.iter().any(|mx| mx.host.is_empty()) {
        return Route::RefusesMail;
    }

    hosts.sort_by_key(|mx| mx.priority);
    Route::ToHosts(hosts)
}

/// Why we could not learn where a domain's mail lives.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// DNS itself failed (network trouble, no resolver). This is a
    /// *temporary* condition — queue and retry, never bounce on it.
    #[error("dns lookup failed: {0}")]
    Dns(String),
}

/// Asks DNS where `domain`'s mail lives, and returns the delivery plan.
///
/// This is [`plan`] fed by a real MX lookup ([`hickory_resolver`]). A domain
/// with *no* MX records is not an error — it falls back to the domain
/// itself, per RFC 5321 §5.1.
///
/// # Errors
/// [`RouteError::Dns`] when resolution itself fails. Treat it as temporary:
/// the right response is requeue-and-retry, not a bounce.
pub async fn lookup(domain: &str) -> Result<Route, RouteError> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::error::ResolveErrorKind;

    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().map_err(|e| RouteError::Dns(e.to_string()))?;

    match resolver.mx_lookup(domain).await {
        Ok(answer) => {
            let records = answer
                .iter()
                .map(|r| MxHost {
                    priority: r.preference(),
                    host: r.exchange().to_utf8(),
                })
                .collect();
            Ok(plan(domain, records))
        }
        // "No MX records" is an answer, not a failure: implicit-MX fallback.
        Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
            Ok(plan(domain, vec![]))
        }
        Err(e) => Err(RouteError::Dns(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mx(priority: u16, host: &str) -> MxHost {
        MxHost {
            priority,
            host: host.to_string(),
        }
    }

    #[test]
    fn hosts_are_dialed_lowest_priority_first() {
        let route = plan(
            "example.com",
            vec![mx(20, "backup.example.com"), mx(10, "primary.example.com")],
        );
        assert_eq!(
            route,
            Route::ToHosts(vec![
                mx(10, "primary.example.com"),
                mx(20, "backup.example.com"),
            ])
        );
    }

    #[test]
    fn no_mx_at_all_falls_back_to_the_domain_itself() {
        // RFC 5321 §5.1: a domain with no MX but an address record still
        // receives mail at that address ("implicit MX").
        let route = plan("example.com", vec![]);
        assert_eq!(route, Route::ToHosts(vec![mx(0, "example.com")]));
    }

    #[test]
    fn null_mx_means_the_domain_refuses_mail() {
        // RFC 7505: `MX 0 .` is a deliberate "we accept no mail."
        let route = plan("example.com", vec![mx(0, ".")]);
        assert_eq!(route, Route::RefusesMail);
    }

    #[test]
    fn a_trailing_dot_on_hostnames_is_normalized_away() {
        // DNS answers often come back fully-qualified: "mx1.example.com."
        let route = plan("example.com", vec![mx(10, "mx1.example.com.")]);
        assert_eq!(route, Route::ToHosts(vec![mx(10, "mx1.example.com")]));
    }

    /// Network test — run explicitly: `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires network"]
    async fn gmail_publishes_mx_hosts() {
        let route = lookup("gmail.com").await.unwrap();
        match route {
            Route::ToHosts(hosts) => {
                assert!(!hosts.is_empty());
                assert!(hosts.iter().any(|h| h.host.contains("google")));
            }
            other => panic!("expected hosts for gmail.com, got {other:?}"),
        }
    }

    /// Network test — example.com publishes a real null MX (`MX 0 .`),
    /// the polite "we accept no mail" of RFC 7505.
    #[tokio::test]
    #[ignore = "requires network"]
    async fn example_com_declares_it_refuses_mail() {
        let route = lookup("example.com").await.unwrap();
        assert_eq!(route, Route::RefusesMail);
    }
}
