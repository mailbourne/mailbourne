//! # blocklist — is this IP carrying baggage?
//!
//! Cloud IPs are recycled; yours may have been a spammer's last month.
//! DNS-based blocklists (Spamhaus, Barracuda, SpamCop) are queried by
//! reversing the IP's octets under the list's zone — a listing means many
//! receivers will refuse or junk your mail no matter how perfect your
//! records are. Reputation is social, not technical; this probe at least
//! makes it *visible*.
