//! # compose — write a proper letter
//!
//! A minimal, correct RFC 5322 message: the headers receivers *require*
//! (`From`, `Date`), the ones they *expect* (`To`, `Subject`,
//! `Message-ID` — Gmail treats a missing Message-ID as a spam signal),
//! CRLF line endings throughout, and the body.
//!
//! [`plain_text`] stays deliberately simple: one part, no ceremony, and it
//! is what the engine proves itself with.
//!
//! [`rich`] is the same letter with more in it — an HTML rendering beside
//! the text, files traveling alongside — and it is built from the same
//! headers plus the pieces in [`mime`](crate::shared::mime). It shapes the
//! tree every mail client expects:
//!
//! ```text
//! text only                    text/plain
//! text + html                  multipart/alternative
//!                                text/plain
//!                                text/html
//! text + files                 multipart/mixed
//!                                text/plain
//!                                the files
//! text + html + files          multipart/mixed
//!                                multipart/alternative
//!                                  text/plain
//!                                  text/html
//!                                the files
//! ```
//!
//! The text part is never optional. A reader whose client shows no HTML, or
//! who has turned it off, still gets the letter; and a message with no text
//! alternative scores worse with spam filters.

use crate::shared::core::{EmailAddress, Message};
use crate::shared::mime::{self, Attachment};

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
    // Through `header_value`, which encodes anything outside ASCII and drops
    // CR and LF. A raw subject is an invalid header the moment someone
    // writes in Indonesian, and a subject carrying a newline could inject a
    // `Bcc:` of its own.
    raw.push_str(&format!("Subject: {}\r\n", mime::header_value(subject)));
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

/// A letter with an optional HTML rendering and any files alongside.
///
/// `text` is required and is what a reader gets when HTML is unavailable.
/// `html` is an alternative rendering of the *same* words, not extra
/// content — a client shows one or the other, never both.
///
/// With no html and no files this is [`plain_text`] exactly, so the simple
/// case stays simple and pays nothing for the general one.
pub fn rich(
    from: &EmailAddress,
    to: &EmailAddress,
    subject: &str,
    text: &str,
    html: Option<&str>,
    attachments: &[Attachment],
    id_host: &str,
) -> Message {
    if html.is_none() && attachments.is_empty() {
        return plain_text(from, to, subject, text, id_host);
    }

    // The body of the letter: one part, or the two renderings of it.
    let (body_type, body) = match html {
        Some(html) => {
            let (content_type, body) = mime::multipart(
                "alternative",
                &[
                    mime::text_part("plain", text),
                    mime::text_part("html", html),
                ],
            );
            (content_type, body)
        }
        None => (
            "text/plain; charset=utf-8".to_string(),
            mime::quoted_printable(text),
        ),
    };

    let (content_type, body) = if attachments.is_empty() {
        (body_type, body)
    } else {
        // The letter becomes the first part, the files follow it.
        let mut first = String::new();
        first.push_str(&format!("Content-Type: {body_type}\r\n"));
        if html.is_none() {
            first.push_str("Content-Transfer-Encoding: quoted-printable\r\n");
        }
        first.push_str("\r\n");
        first.push_str(&body);
        first.push_str("\r\n");

        let mut parts = vec![first];
        parts.extend(attachments.iter().map(|a| a.to_part()));
        mime::multipart("mixed", &parts)
    };

    let mut raw = headers(from, to, subject, id_host);
    raw.push_str(&format!("Content-Type: {content_type}\r\n"));
    // A single text body still needs its encoding declared; a multipart one
    // declares the encoding on each of its parts instead.
    if html.is_none() && attachments.is_empty() {
        raw.push_str("Content-Transfer-Encoding: quoted-printable\r\n");
    }
    raw.push_str("\r\n");
    raw.push_str(&body);
    Message::from_raw(raw.into_bytes())
}

/// The headers every message carries, whatever its shape.
fn headers(from: &EmailAddress, to: &EmailAddress, subject: &str, id_host: &str) -> String {
    let date = chrono::Local::now().to_rfc2822();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut raw = String::new();
    raw.push_str(&format!("From: <{from}>\r\n"));
    raw.push_str(&format!("To: <{to}>\r\n"));
    raw.push_str(&format!("Subject: {}\r\n", mime::header_value(subject)));
    raw.push_str(&format!("Date: {date}\r\n"));
    raw.push_str(&format!("Message-ID: <{nanos}.mb@{id_host}>\r\n"));
    raw.push_str("MIME-Version: 1.0\r\n");
    raw
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

    fn addr(a: &str) -> EmailAddress {
        EmailAddress::parse(a).unwrap()
    }

    fn build(text: &str, html: Option<&str>, files: &[Attachment]) -> String {
        let msg = rich(
            &addr("alice@us.example"),
            &addr("bob@fake.mx"),
            "hello there",
            text,
            html,
            files,
            "mail.us.example",
        );
        String::from_utf8(msg.raw().to_vec()).unwrap()
    }

    /// The boundary a Content-Type header declares.
    fn boundary_of(header_line: &str) -> String {
        header_line
            .split("boundary=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("a multipart declares its boundary")
            .to_string()
    }

    #[test]
    fn with_no_html_and_no_files_rich_is_exactly_plain_text() {
        let text = build("just words", None, &[]);
        assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(
            !text.contains("multipart"),
            "nothing is paid for the general case"
        );
        assert!(text.contains("\r\n\r\njust words"));
    }

    #[test]
    fn text_and_html_become_alternative_renderings_of_one_letter() {
        let text = build(
            "Your code is 002151.",
            Some("<p>Your code is <b>002151</b>.</p>"),
            &[],
        );
        let header = text
            .lines()
            .find(|l| l.starts_with("Content-Type:"))
            .unwrap();
        assert!(header.contains("multipart/alternative"), "{header}");
        let b = boundary_of(header);

        // Both renderings are present, plain first — a client takes the last
        // one it understands, so the richest must come last.
        let plain_at = text.find("Content-Type: text/plain").expect("plain part");
        let html_at = text.find("Content-Type: text/html").expect("html part");
        assert!(plain_at < html_at, "plain must come before html");
        assert_eq!(text.matches(&format!("--{b}\r\n")).count(), 2);
        assert!(text.ends_with(&format!("--{b}--\r\n")));
        assert!(text.contains("<p>Your code is =3Cb=3E") || text.contains("<p>Your code is <b>"));
    }

    #[test]
    fn a_file_wraps_the_letter_in_a_mixed_tree() {
        let pdf = Attachment::new("certificate.pdf", b"%PDF-1.7 pretend".to_vec());
        let text = build(
            "Your certificate is attached.",
            None,
            std::slice::from_ref(&pdf),
        );
        let header = text
            .lines()
            .find(|l| l.starts_with("Content-Type:"))
            .unwrap();
        assert!(header.contains("multipart/mixed"), "{header}");

        // The letter is still readable text, and the file declares itself.
        assert!(text.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(text.contains("Content-Type: application/pdf"));
        assert!(text.contains("Content-Disposition: attachment; filename=\"certificate.pdf\""));
        assert!(text.contains(&crate::shared::mime::base64_wrapped(b"%PDF-1.7 pretend")));
    }

    #[test]
    fn html_and_a_file_nest_alternative_inside_mixed() {
        let pdf = Attachment::new("certificate.pdf", b"bytes".to_vec());
        let text = build(
            "plain words",
            Some("<b>rich words</b>"),
            std::slice::from_ref(&pdf),
        );
        let outer = text
            .lines()
            .find(|l| l.starts_with("Content-Type:"))
            .unwrap();
        assert!(outer.contains("multipart/mixed"), "{outer}");
        let outer_b = boundary_of(outer);

        // The inner alternative is a different boundary, nested inside.
        let inner = text
            .lines()
            .find(|l| l.contains("multipart/alternative"))
            .expect("the two renderings are still alternatives");
        let inner_b = boundary_of(inner);
        assert_ne!(outer_b, inner_b, "a nested part needs its own boundary");
        assert!(text.contains("Content-Type: text/plain"));
        assert!(text.contains("Content-Type: text/html"));
        assert!(text.contains("Content-Type: application/pdf"));
        // Outer: the letter and the file. Inner: the two renderings.
        assert_eq!(text.matches(&format!("--{outer_b}\r\n")).count(), 2);
        assert_eq!(text.matches(&format!("--{inner_b}\r\n")).count(), 2);
    }

    #[test]
    fn several_files_each_get_their_own_part_and_their_own_name() {
        let files = vec![
            Attachment::new("one.pdf", b"a".to_vec()),
            Attachment::new("two.png", b"b".to_vec()),
        ];
        let text = build("two files", None, &files);
        assert!(text.contains("filename=\"one.pdf\"") && text.contains("filename=\"two.png\""));
        assert!(
            text.contains("Content-Type: application/pdf")
                && text.contains("Content-Type: image/png")
        );
    }

    #[test]
    fn a_subject_in_another_language_survives_the_header() {
        let msg = rich(
            &addr("a@b.test"),
            &addr("c@d.test"),
            "Sertifikat — peserta",
            "hi",
            None,
            &[],
            "mail.b.test",
        );
        let text = String::from_utf8(msg.raw().to_vec()).unwrap();
        assert!(
            text.contains("Subject: =?utf-8?B?"),
            "an encoded word, not raw bytes"
        );
        assert!(!text.contains("Sertifikat — peserta"));
    }

    #[test]
    fn a_subject_can_neither_smuggle_a_header_nor_arrive_as_raw_bytes() {
        // Header injection: a newline in the subject would start a new
        // header, and `Bcc:` is the one an attacker wants.
        let msg = plain_text(
            &addr("a@b.test"),
            &addr("c@d.test"),
            "Invoice\r\nBcc: thief@evil.test",
            "body",
            "mail.b.test",
        );
        let text = String::from_utf8(msg.raw().to_vec()).unwrap();
        assert!(
            !text.contains("Bcc:") || text.contains("InvoiceBcc:"),
            "no new header was created"
        );
        assert_eq!(
            text.lines().filter(|l| l.starts_with("Subject:")).count(),
            1
        );
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
