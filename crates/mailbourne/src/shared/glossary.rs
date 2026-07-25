//! # glossary — plain words for the jargon
//!
//! Mail is an alphabet soup: SMTP, TLS, STARTTLS, DKIM, SPF, DMARC, SRS, ARC,
//! MX, PTR. Every abbreviation mailbourne shows should be one plain sentence
//! away from being understood — so this is the single, curated source of
//! those sentences. The console, the logs, the inspector, and the
//! `mailbourne explain` command all read from here, so a term is described
//! the same way everywhere (and never by a guess).

/// One glossary entry: the abbreviation, what it stands for, and a plain,
/// analogy-friendly explanation a beginner can act on.
#[derive(Debug, Clone, Copy)]
pub struct Term {
    /// The abbreviation as shown (e.g. `"STARTTLS"`).
    pub abbr: &'static str,
    /// What the letters stand for (e.g. `"Start TLS"`).
    pub full: &'static str,
    /// A plain-English, one-or-two-sentence description.
    pub plain: &'static str,
}

/// Where to send someone who wants more than the one-liner.
pub fn learn_more(abbr: &str) -> String {
    format!("mailbourne.zebflow.com/go/{}", abbr.to_ascii_lowercase())
}

/// The description for `abbr`, matched case-insensitively.
pub fn describe(abbr: &str) -> Option<&'static Term> {
    GLOSSARY.iter().find(|t| t.abbr.eq_ignore_ascii_case(abbr))
}

/// Every term, for a full listing.
pub fn all() -> &'static [Term] {
    GLOSSARY
}

/// The curated glossary. Keep the plain lines short, concrete, and honest —
/// they are what a first-time operator learns mail from.
static GLOSSARY: &[Term] = &[
    Term {
        abbr: "SMTP",
        full: "Simple Mail Transfer Protocol",
        plain: "The language mail servers speak to hand a message from one to \
                the next — the postal workers' routine for passing a letter along.",
    },
    Term {
        abbr: "TLS",
        full: "Transport Layer Security",
        plain: "Encryption for a connection, so no one in between can read \
                what's sent. It's the 's' in https.",
    },
    Term {
        abbr: "STARTTLS",
        full: "Start TLS",
        plain: "Upgrades an already-open plain connection to an encrypted one \
                mid-conversation — like switching to a private line before you \
                say anything sensitive, such as a password.",
    },
    Term {
        abbr: "AUTH",
        full: "Authentication",
        plain: "Proving you are who you claim — a username and password — before \
                the server will send mail on your behalf.",
    },
    Term {
        abbr: "DKIM",
        full: "DomainKeys Identified Mail",
        plain: "A tamper-proof wax seal the sender presses into a message; the \
                receiver checks it's unbroken to trust the mail really came from \
                that domain and wasn't altered.",
    },
    Term {
        abbr: "SPF",
        full: "Sender Policy Framework",
        plain: "A domain's public list of which servers are allowed to send its \
                mail — the receiver checks the sender is on the list.",
    },
    Term {
        abbr: "DMARC",
        full: "Domain-based Message Authentication, Reporting & Conformance",
        plain: "The rule tying SPF and DKIM together: trust the mail if the seal \
                (DKIM) or the sender list (SPF) checks out — and say what to do \
                when neither does.",
    },
    Term {
        abbr: "SRS",
        full: "Sender Rewriting Scheme",
        plain: "When you forward mail, you put your own return address on the \
                envelope, so bounces come back to you and your server isn't \
                blamed for the original sender's mail.",
    },
    Term {
        abbr: "ARC",
        full: "Authenticated Received Chain",
        plain: "A signed \"I checked this and it was legit when it reached me\" \
                note a forwarder adds, so a receiver that trusts it honors the \
                original checks even if forwarding broke them.",
    },
    Term {
        abbr: "MX",
        full: "Mail eXchange record",
        plain: "The DNS entry naming which server receives a domain's mail — the \
                address on the mailbox, so senders know where to deliver.",
    },
    Term {
        abbr: "PTR",
        full: "Pointer record (reverse DNS)",
        plain: "Maps an IP address back to a hostname. Receivers check it to see \
                a sending server 'has a name' — a basic sign it isn't a random \
                spammer.",
    },
    Term {
        abbr: "DNS",
        full: "Domain Name System",
        plain: "The internet's address book — it turns names like ours.com into \
                the records (IP, MX, TXT) that make mail routing and checks work.",
    },
    Term {
        abbr: "TXT",
        full: "DNS text record",
        plain: "A free-form line of text published in DNS — where SPF, DKIM, and \
                DMARC values live for the world to read.",
    },
    Term {
        abbr: "MTA",
        full: "Mail Transfer Agent",
        plain: "A server in 'receive from other servers' mode (port 25): no \
                login, and it only accepts mail for its own domains.",
    },
    Term {
        abbr: "MSA",
        full: "Mail Submission Agent",
        plain: "A server in 'accept from a logged-in user' mode (port 587): it \
                requires a password, then sends that user's mail onward to anyone.",
    },
    Term {
        abbr: "Argon2",
        full: "Argon2 password hashing",
        plain: "The algorithm that turns a password into a scrambled fingerprint \
                which can be checked but never reversed — so a stolen config file \
                never reveals anyone's password.",
    },
    Term {
        abbr: "Maildir",
        full: "Maildir mailbox format",
        plain: "A way of storing a mailbox as one file per message (used by \
                Postfix and Dovecot). It's how mailbourne keeps received mail.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_is_case_insensitive_and_honest_about_the_unknown() {
        assert_eq!(describe("starttls").unwrap().abbr, "STARTTLS");
        assert_eq!(describe("STARTTLS").unwrap().full, "Start TLS");
        assert!(describe("not-a-term").is_none());
    }

    #[test]
    fn every_entry_is_filled_in_and_unique() {
        for term in all() {
            assert!(!term.abbr.is_empty());
            assert!(!term.full.is_empty(), "{} has no expansion", term.abbr);
            assert!(
                term.plain.len() > 30,
                "{} needs a real description",
                term.abbr
            );
        }
        // No duplicate abbreviations (case-insensitive).
        for (i, a) in all().iter().enumerate() {
            for b in &all()[i + 1..] {
                assert!(!a.abbr.eq_ignore_ascii_case(b.abbr), "duplicate {}", a.abbr);
            }
        }
    }

    #[test]
    fn learn_more_builds_a_lowercased_go_link() {
        assert_eq!(learn_more("DKIM"), "mailbourne.zebflow.com/go/dkim");
    }
}
