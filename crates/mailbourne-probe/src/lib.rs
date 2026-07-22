//! # mailbourne-probe — questions we ask the world
//!
//! A probe asks **one question** about how the outside world sees a mail
//! server, and returns **typed evidence** — never a bare bool, never a
//! rendered string. The inspector judges evidence; renderers display it; this
//! crate only gathers it.
//!
//! Three rules keep probes honest:
//!
//! 1. **Read-only.** A probe never changes anything, anywhere.
//! 2. **Evidence, not verdicts.** `PtrEvidence { ptr_hostname, forward_ip,
//!    matches }` lets the caller see *why*, not just whether.
//! 3. **The world is the database.** Probes are how mailbourne re-derives
//!    all state — run them anytime, trust only what they return.
//!
//! Modules: [`dns`] (MX/SPF/DKIM/PTR lookups), [`dial`] (can we reach a
//! port?), [`tls`] (does the handshake succeed?), [`blocklist`] (is this IP
//! on a DNSBL?).

pub mod blocklist;
pub mod dial;
pub mod dns;
pub mod tls;
