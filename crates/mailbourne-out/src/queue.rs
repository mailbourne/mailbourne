//! # 5 · queue — if not now, safely later
//!
//! Email's superpower is that a down server loses nothing: messages wait in
//! a **durable queue** (on disk, in the mount — surviving restarts) until
//! delivery succeeds or the retry budget is spent. Accepting a message and
//! then losing it is the one unforgivable failure, so the rule is
//! write-ahead: a message is on disk *before* we tell anyone we've taken
//! responsibility for it.
