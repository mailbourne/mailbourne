//! # cli — the operator console
//!
//! The interactive, terminal-facing surface behind the `mailbourne` binary
//! (feature `cli`, which turns everything on). Everything here renders and
//! prompts; the engine underneath returns data.
//!
//! - [`console`] — the guided setup/status console

pub mod console;
