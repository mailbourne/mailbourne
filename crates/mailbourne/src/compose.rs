//! # compose — write a proper letter
//!
//! A minimal, correct RFC 5322 message: the headers receivers *require*
//! (`From`, `Date`), the ones they *expect* (`To`, `Subject`,
//! `Message-ID` — Gmail treats a missing Message-ID as a spam signal),
//! CRLF line endings throughout, and the body.
//!
//! This is deliberately simple — plain-text, single part. Rich messages
//! (HTML, attachments, MIME trees) will ride `mail-builder`; this exists
//! so the engine can prove itself end to end with zero ceremony.

use mailbourne_core::{EmailAddress, Message};

/// Composes a plain-text RFC 5322 message.
///
/// `id_host` seasons the `Message-ID` (convention: your mail hostname).
/// The `Date` header is stamped with the current local time.
pub fn plain_text(
    from: &EmailAddress,
    to: &EmailAddress,
    subject: &str,
    body: &str,
    id_host: &str,
) -> Message {
    let date = chrono::Local::now().to_rfc2822();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let message_id = format!("<{nanos}.mb@{id_host}>");

    let mut raw = String::new();
    raw.push_str(&format!("From: <{from}>\r\n"));
    raw.push_str(&format!("To: <{to}>\r\n"));
    raw.push_str(&format!("Subject: {subject}\r\n"));
    raw.push_str(&format!("Date: {date}\r\n"));
    raw.push_str(&format!("Message-ID: {message_id}\r\n"));
    raw.push_str("MIME-Version: 1.0\r\n");
    raw.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    raw.push_str("\r\n");
    // Normalize the body to CRLF without doubling existing CRLFs.
    for line in body.split('\n') {
        raw.push_str(line.trim_end_matches('\r'));
        raw.push_str("\r\n");
    }
    Message::from_raw(raw.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compose() -> String {
        let msg = plain_text(
            &EmailAddress::parse("alice@us.example").unwrap(),
            &EmailAddress::parse("bob@fake.mx").unwrap(),
            "hello there",
            "line one\nline two",
            "mail.us.example",
        );
        String::from_utf8(msg.raw().to_vec()).unwrap()
    }

    #[test]
    fn the_required_and_expected_headers_are_present() {
        let text = compose();
        assert!(text.contains("From: <alice@us.example>\r\n"));
        assert!(text.contains("To: <bob@fake.mx>\r\n"));
        assert!(text.contains("Subject: hello there\r\n"));
        assert!(text.contains("Date: "), "Date is REQUIRED by RFC 5322");
        assert!(
            text.contains("Message-ID: <") && text.contains("@mail.us.example>"),
            "a missing Message-ID reads as spam to Gmail"
        );
    }

    #[test]
    fn headers_and_body_are_separated_by_a_blank_line_with_crlf_endings() {
        let text = compose();
        assert!(text.contains("\r\n\r\nline one\r\nline two\r\n"));
        assert!(!text.contains("\n\n"), "bare LFs have no place on the wire");
    }
}
