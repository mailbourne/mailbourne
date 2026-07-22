//! # send wing — will the world trust my mail?
//!
//! S1–S7: outbound port 25 reachable, PTR matches (caller ID), SPF (guest
//! list), DKIM (wax seal), DMARC (the judge that aligns them), blocklist
//! status (IP baggage) — and then the ★ proof: a real signed message
//! accepted by a real inbox, with SPF/DKIM/DMARC all reading PASS.
//!
//! Dependency rule: S5 (DMARC) stays [`Pending`](crate::atom::Status)
//! until S3+S4 exist — DMARC is a judge; it needs SPF and DKIM to testify.
