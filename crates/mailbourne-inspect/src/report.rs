//! # report — the one struct every skin renders
//!
//! A [`ChecklistReport`] is the inspector's complete answer for a domain:
//! every atom, with status and evidence, in wing order. The log narrator
//! diffs two reports to speak in deltas; the CLI prints one as cards;
//! `--json` serializes it; a downstream app walks `items` and renders its
//! own onboarding UI. One engine, many skins.

use crate::atom::ChecklistItem;

/// The inspector's complete findings for one domain.
#[derive(Debug, Clone)]
pub struct ChecklistReport {
    /// The domain that was examined.
    pub domain: String,
    /// Every checklist item, in wing order (identity, send, receive).
    pub items: Vec<ChecklistItem>,
}

impl ChecklistReport {
    /// True when every item passes — both wings green, a real mail server.
    pub fn all_green(&self) -> bool {
        self.items
            .iter()
            .all(|i| i.status == crate::atom::Status::Pass)
    }
}
