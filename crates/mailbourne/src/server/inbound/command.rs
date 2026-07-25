//! # command — understand what the client said
//!
//! Every line a connecting client sends is an SMTP command. This parses one
//! line into a typed [`SmtpCommand`] — pure, no I/O, so the whole grammar is
//! testable without a socket. It is the receiving mirror of the replies our
//! outbound side reads.

/// A single SMTP command from a connecting client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    /// `EHLO <domain>` — the modern greeting; the client names itself and
    /// asks what we support.
    Ehlo(String),
    /// `HELO <domain>` — the legacy greeting.
    Helo(String),
    /// `MAIL FROM:<addr>` — the envelope sender. Empty (`<>`) is the null
    /// sender used by bounce messages, and is legitimate.
    MailFrom(String),
    /// `RCPT TO:<addr>` — one envelope recipient (may repeat).
    RcptTo(String),
    /// `DATA` — "here comes the letter."
    Data,
    /// `STARTTLS` — "let's make this private."
    StartTls,
    /// `RSET` — forget this transaction, start fresh.
    Rset,
    /// `NOOP` — do nothing (a keep-alive).
    Noop,
    /// `QUIT` — goodbye.
    Quit,
    /// Anything we don't recognise — the session answers `500`.
    Unknown(String),
}

/// Parses one command line (without its trailing CRLF) into an
/// [`SmtpCommand`].
///
/// The verb is case-insensitive (`DATA` == `data`). For `MAIL`/`RCPT` the
/// address is taken from between `<` and `>`; any ESMTP parameters after it
/// (e.g. `SIZE=1000`) are ignored here — later stages apply policy.
pub fn parse(line: &str) -> SmtpCommand {
    let line = line.trim();
    let (verb, rest) = match line.split_once(char::is_whitespace) {
        Some((v, r)) => (v, r.trim()),
        None => (line, ""),
    };
    match verb.to_ascii_uppercase().as_str() {
        "EHLO" => SmtpCommand::Ehlo(rest.to_string()),
        "HELO" => SmtpCommand::Helo(rest.to_string()),
        "MAIL" => SmtpCommand::MailFrom(extract_path(rest)),
        "RCPT" => SmtpCommand::RcptTo(extract_path(rest)),
        "DATA" => SmtpCommand::Data,
        "STARTTLS" => SmtpCommand::StartTls,
        "RSET" => SmtpCommand::Rset,
        "NOOP" => SmtpCommand::Noop,
        "QUIT" => SmtpCommand::Quit,
        _ => SmtpCommand::Unknown(line.to_string()),
    }
}

/// Extracts the address from `FROM:<addr>` / `TO:<addr>`. The address lives
/// between the angle brackets (`<>` yields the empty null sender); ESMTP
/// parameters trailing the `>` are left for later stages.
fn extract_path(rest: &str) -> String {
    if let (Some(lt), Some(gt)) = (rest.find('<'), rest.rfind('>')) {
        if lt < gt {
            return rest[lt + 1..gt].trim().to_string();
        }
    }
    if let Some(colon) = rest.find(':') {
        return rest[colon + 1..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greetings_carry_the_client_name_case_insensitively() {
        assert_eq!(
            parse("EHLO mail.example.com"),
            SmtpCommand::Ehlo("mail.example.com".into())
        );
        assert_eq!(parse("ehlo x"), SmtpCommand::Ehlo("x".into()));
        assert_eq!(
            parse("HELO legacy.example"),
            SmtpCommand::Helo("legacy.example".into())
        );
    }

    #[test]
    fn mail_from_extracts_the_envelope_sender() {
        assert_eq!(
            parse("MAIL FROM:<alice@example.com>"),
            SmtpCommand::MailFrom("alice@example.com".into())
        );
    }

    #[test]
    fn the_null_sender_is_kept_as_empty_not_dropped() {
        // Bounce messages use MAIL FROM:<> — an empty envelope sender is
        // legitimate and must not be confused with a parse failure.
        assert_eq!(parse("MAIL FROM:<>"), SmtpCommand::MailFrom(String::new()));
    }

    #[test]
    fn esmtp_parameters_after_the_address_are_ignored() {
        assert_eq!(
            parse("MAIL FROM:<a@b> SIZE=1000"),
            SmtpCommand::MailFrom("a@b".into())
        );
    }

    #[test]
    fn rcpt_to_extracts_a_recipient() {
        assert_eq!(
            parse("RCPT TO:<bob@example.com>"),
            SmtpCommand::RcptTo("bob@example.com".into())
        );
    }

    #[test]
    fn the_simple_verbs_parse() {
        assert_eq!(parse("DATA"), SmtpCommand::Data);
        assert_eq!(parse("quit"), SmtpCommand::Quit);
        assert_eq!(parse("STARTTLS"), SmtpCommand::StartTls);
        assert_eq!(parse("RSET"), SmtpCommand::Rset);
        assert_eq!(parse("NOOP"), SmtpCommand::Noop);
    }

    #[test]
    fn anything_unrecognised_is_unknown() {
        assert_eq!(
            parse("WHAT IS THIS"),
            SmtpCommand::Unknown("WHAT IS THIS".into())
        );
    }
}
