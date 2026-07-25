//! # receive wing — can the world reach me?
//!
//! R1–R6: MX points here, inbound port 25 answers from the outside (this
//! probe must dial from an external vantage point — a server cannot knock
//! on its own front door), MTA-STS forces TLS, optional DANE pins the cert,
//! autoconfig lets clients set themselves up — and the ★ proof: watching a
//! real Gmail server connect, pass SPF/DKIM checks, and deliver into a
//! local mailbox, live in the logs.
