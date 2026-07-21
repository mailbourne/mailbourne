//! # ptr — does the IP's name match forward DNS?
//!
//! PTR is caller ID for servers: the *reverse* lookup from IP back to a
//! hostname. Receivers expect **forward-confirmed rDNS**: the IP resolves
//! to a name, and that name resolves back to the same IP. A default VPS
//! hostname here is a near-guaranteed spam flag.
//!
//! PTR records are owned by whoever owns the IP (the VPS provider), not by
//! your DNS zone — this probe detects the mismatch; fixing it needs a
//! provider ticket, and the doctor supplies the text.
