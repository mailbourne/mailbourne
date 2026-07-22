//! # atom — one checklist item, as data
//!
//! Every check the inspector performs is an *atom* with five faces: WHAT (an
//! analogy), WHY (the consequence), DO (a copy-paste artifact and
//! provider-specific instructions), VERIFY (live probe evidence), and LEARN
//! (a pointer into the built-in encyclopedia). The same atom renders as a
//! one-line log delta, a full card in `mailbourne inspect`, or a widget in a
//! downstream app — because it is data, not text.

/// The verified state of one checklist item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// A live probe confirmed this is correctly set up. Never claimed
    /// without evidence — a wrong green checkmark is the unforgivable bug.
    Pass,
    /// A live probe confirmed this is missing or wrong.
    Fail,
    /// Not yet checkable (e.g. waiting on DNS propagation, or blocked by a
    /// dependency such as DMARC needing SPF+DKIM first).
    Pending,
    /// Cannot be fixed from here — it belongs to an outside party (PTR
    /// records, port-25 unblocking). The item carries the ticket text.
    Blocked,
}

/// One checklist item: identity, verdict, teaching, and the fix.
#[derive(Debug, Clone)]
pub struct ChecklistItem {
    /// Stable identifier (`"S4"` = send-wing item 4, `"R1"` = receive-wing
    /// item 1, `"I2"` = identity item 2).
    pub id: String,
    /// Short human title (`"DKIM record published"`).
    pub title: String,
    /// The verified state, backed by probe evidence.
    pub status: Status,
    /// WHAT: plain-language explanation with one analogy
    /// ("DKIM is a wax seal for your emails…").
    pub what: String,
    /// WHY: the consequence of leaving this red
    /// ("without it, Gmail treats your mail as unsigned paper…").
    pub why: String,
    /// DO: the copy-paste artifact, when one exists (a DNS record, a
    /// command, a support-ticket text).
    pub artifact: Option<String>,
    /// LEARN: topic name for `mailbourne learn <topic>`.
    pub learn: String,
}
