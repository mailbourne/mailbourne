//! # spf — who is allowed to send for this domain?
//!
//! SPF is the guest list: a TXT record (`v=spf1 …`) naming the IPs allowed
//! to send mail *from this domain's envelope sender*. Receivers check the
//! connecting IP against it. Crucially, SPF judges the **envelope**
//! `MAIL FROM` — not the `From:` header your mail client shows. Aligning
//! those two is DMARC's job.
//!
//! This probe fetches and parses the record, and answers: is a given IP on
//! the list?
