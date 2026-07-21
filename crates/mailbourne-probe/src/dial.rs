//! # dial — can we reach a port from here?
//!
//! The humblest probe, and the one that catches the most common failure:
//! **outbound port 25 is blocked by default on most clouds** (it's the
//! classic spam cannon). This probe dials a TCP address with a timeout and
//! reports what happened — connected, refused, or filtered-into-silence
//! (the telltale signature of a provider block).
//!
//! Used by the doctor's S1 (can I dial out to a remote 25?) and, from an
//! external vantage point, R2 (can the world dial *my* 25?).
