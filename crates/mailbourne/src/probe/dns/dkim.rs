//! # dkim — is the public key published?
//!
//! DKIM signatures are made with a private key that never leaves the server;
//! the world verifies them against a public key published in DNS at
//! `<selector>._domainkey.<domain>`. This probe fetches that record and —
//! the check nobody else does — compares it against the key on disk, so the
//! inspector can catch the classic silent failure: a re-created volume whose
//! new key no longer matches the published record.
