//! # mx — where does this domain's mail live?
//!
//! To deliver to `bob@example.com`, a sender queries `example.com`'s **MX
//! records**: a priority-ordered list of hostnames ("try this server first,
//! then that one"). Lower number = higher priority. No MX at all falls back
//! to the domain's A record (RFC 5321 §5.1); `MX 0 .` ("null MX", RFC 7505)
//! means "this domain refuses all mail."
//!
//! The outbound sender ([`mailbourne-out`]'s `route` step) and the doctor's
//! R1 check both ride this probe — one implementation, two consumers.
