//! # mailbourne-doctor — the judge
//!
//! Turns probe evidence into a [`report::ChecklistReport`]: which checks
//! pass, which fail, what to do about each, and the explanation a beginner
//! deserves. **This crate returns data and renders nothing** — the log
//! narrator, the CLI, and any downstream app's UI are all skins over the
//! same report. That rule is enforced by the dependency graph: no terminal
//! or UI crates may appear in this crate's tree.
//!
//! The checklist has three wings: [`wings::identity`] (who am I?),
//! [`wings::send`] (will the world trust me?), and [`wings::receive`]
//! (can the world reach me?). Each item is an [`atom::ChecklistItem`] —
//! WHAT/WHY/DO/VERIFY/LEARN as structured fields.
//!
//! The doctor's verification accuracy is the highest-stakes code in the
//! project: **a wrong green checkmark is the one unforgivable bug.**

pub mod atom;
pub mod report;
pub mod wings;
