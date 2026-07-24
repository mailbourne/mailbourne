//! # mailbourne-in — a message must arrive
//!
//! The receiving side of mail: the server half of the RFC 5321 dialogue —
//! the mirror of `mailbourne-out`'s `conversation`. Where `out` dials and
//! speaks as the *client*, `in` listens and answers as the *server*: it
//! reads EHLO / MAIL / RCPT / DATA, runs the acceptance pipeline, and hands
//! accepted mail to storage.
//!
//! Read the modules in the order a received message travels:
//! [`command`] (understand what the client said) → session → pipeline →
//! delivery. Only `command` exists so far.

pub mod command;
