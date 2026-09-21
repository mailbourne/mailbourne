//! # mime — the parts a rich letter is made of
//!
//! A plain-text message is one body after the headers. Anything richer is a
//! *tree*: alternative renderings of the same words, and files travelling
//! alongside them. This module holds the pieces that tree is built from —
//! boundaries, transfer encodings, and the header forms that survive a
//! recipient whose software was written in 1998.
//!
//! It deliberately knows nothing about sending, signing or config. Give it
//! bytes and a filename; it gives you bytes a mail client will understand.
//!
//! ## What the rules are, and why
//!
//! **Lines are at most 76 characters.** SMTP permits 998, but relays have
//! historically mangled longer ones, and base64 at 76 is the convention
//! every client expects.
//!
//! **Text is quoted-printable, files are base64.** Quoted-printable keeps a
//! message legible to a human reading the raw source, which matters when you
//! are debugging why a letter looked wrong. Base64 makes no such promise and
//! is the only safe choice for arbitrary bytes.
//!
//! **Non-ASCII filenames use RFC 2231.** A name like `sertifikat peserta.pdf`
//! is fine; `sertifikat peláatihan.pdf` is not, unless it is encoded. Getting
//! this wrong is how attachments arrive called `=?utf-8?B?…?=`.

use std::fmt::Write as _;

/// The longest line this module will emit, excluding the CRLF.
pub const MAX_LINE: usize = 76;

/// A boundary that cannot appear in the content it separates.
///
/// The randomness matters: a boundary that happens to occur inside an
/// attachment truncates the message at that point, and the failure looks
/// like a corrupt file rather than a collision. Sixteen random bytes make
/// that impossible in practice, and the `=_` prefix cannot begin a base64
/// or quoted-printable line, so it cannot occur by accident either.
pub fn boundary(seed: u128) -> String {
    let mut out = String::from("=_mb_");
    let mut n = seed;
    for _ in 0..22 {
        let d = (n % 36) as u32;
        n /= 36;
        out.push(char::from_digit(d, 36).unwrap_or('0'));
    }
    out
}

/// A boundary seeded from the clock and the address of a local allocation.
///
/// Mailbourne has no random dependency and one is not worth adding for this:
/// what a boundary needs is *uniqueness within one message*, not secrecy.
pub fn fresh_boundary() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let here = &nanos as *const u128 as usize as u128;
    boundary(nanos ^ (here << 64) ^ (here >> 3))
}

/// Encodes text as quoted-printable, wrapped to [`MAX_LINE`].
///
/// Printable ASCII passes through, so a plain English message is still
/// readable in the raw source. Everything else becomes `=XX`. A space or tab
/// at the end of a line is encoded, because trailing whitespace is exactly
/// what relays strip.
pub fn quoted_printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        let mut column = 0usize;
        let bytes = line.as_bytes();
        for (j, &b) in bytes.iter().enumerate() {
            let last = j + 1 == bytes.len();
            let literal = match b {
                b'=' => false,
                b' ' | b'\t' => !last,
                0x21..=0x7e => true,
                _ => false,
            };
            let width = if literal { 1 } else { 3 };
            // A soft break: `=` at the end means "this line continues".
            if column + width > MAX_LINE - 1 {
                out.push_str("=\r\n");
                column = 0;
            }
            if literal {
                out.push(b as char);
            } else {
                let _ = write!(out, "={b:02X}");
            }
            column += width;
        }
    }
    out
}

/// Encodes bytes as base64, wrapped to [`MAX_LINE`], CRLF between lines.
pub fn base64_wrapped(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        raw.push(ALPHABET[(n >> 18) as usize & 63] as char);
        raw.push(ALPHABET[(n >> 12) as usize & 63] as char);
        raw.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        raw.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    let mut out = String::with_capacity(raw.len() + raw.len() / MAX_LINE * 2);
    for (i, chunk) in raw.as_bytes().chunks(MAX_LINE).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

/// A header value that may contain any Unicode, encoded so it survives.
///
/// ASCII passes through untouched, because `Subject: Your code` should read
/// as itself in the raw source. Anything else becomes an RFC 2047 encoded
/// word, which is what a `Subject:` in Indonesian or Arabic needs.
pub fn header_value(value: &str) -> String {
    let clean: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    if clean.is_ascii() {
        return clean;
    }
    format!("=?utf-8?B?{}?=", base64_wrapped(clean.as_bytes()).replace("\r\n", ""))
}

/// A `filename` parameter for `Content-Disposition`.
///
/// ASCII names use the plain form every client has always understood.
/// Anything else uses RFC 2231's `filename*=utf-8''…`, which is what makes
/// a name with an accent or a Javanese character arrive intact instead of
/// as mojibake.
pub fn filename_parameter(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\' && *c != '/')
        .collect();
    let clean = if clean.trim().is_empty() { "attachment".to_string() } else { clean };
    if clean.is_ascii() {
        return format!("filename=\"{clean}\"");
    }
    let mut encoded = String::new();
    for b in clean.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
            encoded.push(*b as char);
        } else {
            let _ = write!(encoded, "%{b:02X}");
        }
    }
    format!("filename*=utf-8''{encoded}")
}

/// The MIME type to declare for a file, from its name.
///
/// A short, honest table rather than a database. Anything unrecognised is
/// `application/octet-stream`, which every client treats as "save this",
/// and which is never wrong, only unhelpful.
pub fn content_type_for(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "json" => "application/json",
        "ics" => "text/calendar; charset=utf-8",
        "zip" => "application/zip",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

/// A file travelling with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The name the recipient sees.
    pub filename: String,
    /// What it is. Taken from the name when not given.
    pub content_type: Option<String>,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl Attachment {
    /// An attachment whose type is read from its filename.
    pub fn new(filename: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { filename: filename.into(), content_type: None, bytes }
    }

    /// An attachment declaring its own type.
    pub fn with_type(filename: impl Into<String>, content_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { filename: filename.into(), content_type: Some(content_type.into()), bytes }
    }

    /// The type this attachment declares on the wire.
    pub fn declared_type(&self) -> String {
        self.content_type
            .clone()
            .unwrap_or_else(|| content_type_for(&self.filename).to_string())
    }

    /// This attachment as one MIME part, headers and body.
    pub fn to_part(&self) -> String {
        let mut part = String::new();
        let _ = write!(part, "Content-Type: {}\r\n", self.declared_type());
        part.push_str("Content-Transfer-Encoding: base64\r\n");
        let _ = write!(part, "Content-Disposition: attachment; {}\r\n", filename_parameter(&self.filename));
        part.push_str("\r\n");
        part.push_str(&base64_wrapped(&self.bytes));
        part.push_str("\r\n");
        part
    }
}

/// One text body as a MIME part. `subtype` is `plain` or `html`.
pub fn text_part(subtype: &str, body: &str) -> String {
    let mut part = String::new();
    let _ = write!(part, "Content-Type: text/{subtype}; charset=utf-8\r\n");
    part.push_str("Content-Transfer-Encoding: quoted-printable\r\n");
    part.push_str("\r\n");
    part.push_str(&quoted_printable(body));
    part.push_str("\r\n");
    part
}

/// Wraps `parts` in a multipart body of the given subtype.
///
/// Answers the `Content-Type` header value and the body, so the caller can
/// put the header wherever its message needs it.
pub fn multipart(subtype: &str, parts: &[String]) -> (String, String) {
    let boundary = fresh_boundary();
    let mut body = String::new();
    // A line for a reader whose client cannot do MIME at all. They are rare
    // now, but the line costs nothing and is the convention.
    body.push_str("This is a message in MIME format.\r\n");
    for part in parts {
        let _ = write!(body, "\r\n--{boundary}\r\n");
        body.push_str(part);
    }
    let _ = write!(body, "\r\n--{boundary}--\r\n");
    (format!("multipart/{subtype}; boundary=\"{boundary}\""), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_boundary_is_unique_and_cannot_start_an_encoded_line() {
        let a = fresh_boundary();
        let b = fresh_boundary();
        assert_ne!(a, b, "two boundaries in one process must differ");
        assert!(a.starts_with("=_mb_"), "{a}");
        // Neither base64 nor quoted-printable can produce a line starting
        // `=_`, so a boundary cannot collide with content by accident.
        assert!(!a.contains(' ') && a.is_ascii());
    }

    #[test]
    fn quoted_printable_keeps_plain_english_readable_and_escapes_the_rest() {
        assert_eq!(quoted_printable("Your code is 002151."), "Your code is 002151.");
        // `=` is the escape character and must itself be escaped.
        assert_eq!(quoted_printable("a=b"), "a=3Db");
        // Non-ASCII becomes its UTF-8 bytes, each escaped.
        assert_eq!(quoted_printable("café"), "caf=C3=A9");
        // Trailing whitespace is what relays strip, so it is encoded.
        assert_eq!(quoted_printable("ends "), "ends=20");
        assert_eq!(quoted_printable("mid space ok"), "mid space ok");
        // Newlines become CRLF and are not escaped.
        assert_eq!(quoted_printable("one\ntwo"), "one\r\ntwo");
    }

    #[test]
    fn quoted_printable_soft_wraps_long_lines_below_the_limit() {
        let long = "x".repeat(300);
        let out = quoted_printable(&long);
        for line in out.split("\r\n") {
            assert!(line.len() <= MAX_LINE, "line of {} chars: {line}", line.len());
        }
        // A soft break is a trailing `=`, and the text survives it.
        assert!(out.contains("=\r\n"));
        assert_eq!(out.replace("=\r\n", ""), long);
    }

    #[test]
    fn base64_matches_the_known_answer_and_wraps() {
        assert_eq!(base64_wrapped(b""), "");
        assert_eq!(base64_wrapped(b"f"), "Zg==");
        assert_eq!(base64_wrapped(b"fo"), "Zm8=");
        assert_eq!(base64_wrapped(b"foo"), "Zm9v");
        assert_eq!(base64_wrapped(b"foob"), "Zm9vYg==");
        assert_eq!(base64_wrapped(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_wrapped(b"foobar"), "Zm9vYmFy");

        let big = vec![0u8; 500];
        for line in base64_wrapped(&big).split("\r\n") {
            assert!(line.len() <= MAX_LINE, "{}", line.len());
        }
    }

    #[test]
    fn a_header_passes_ascii_through_and_encodes_the_rest() {
        assert_eq!(header_value("Your INDERA sign-in code"), "Your INDERA sign-in code");
        assert!(header_value("Sertifikat — peserta").starts_with("=?utf-8?B?"));
        // A header can never carry a newline: that would inject a header.
        assert_eq!(header_value("Subject\r\nBcc: someone@evil.test"), "SubjectBcc: someone@evil.test");
    }

    #[test]
    fn a_filename_is_quoted_when_plain_and_rfc_2231_when_not() {
        assert_eq!(filename_parameter("certificate.pdf"), "filename=\"certificate.pdf\"");
        assert_eq!(filename_parameter("annual report.pdf"), "filename=\"annual report.pdf\"");
        let fancy = filename_parameter("sertifikat peserta — 2026.pdf");
        assert!(fancy.starts_with("filename*=utf-8''"), "{fancy}");
        assert!(fancy.contains("%E2%80%94"), "the em dash is percent-encoded: {fancy}");
        // A path separator or a quote would break out of the header.
        assert_eq!(filename_parameter("../../etc/passwd"), "filename=\"....etcpasswd\"");
        assert_eq!(filename_parameter("   "), "filename=\"attachment\"");
    }

    #[test]
    fn a_file_takes_its_type_from_its_name_unless_it_says_otherwise() {
        assert_eq!(Attachment::new("a.pdf", vec![]).declared_type(), "application/pdf");
        assert_eq!(Attachment::new("a.PNG", vec![]).declared_type(), "image/png");
        assert_eq!(Attachment::new("a.wat", vec![]).declared_type(), "application/octet-stream");
        assert_eq!(Attachment::new("noextension", vec![]).declared_type(), "application/octet-stream");
        assert_eq!(
            Attachment::with_type("a.bin", "application/pdf", vec![]).declared_type(),
            "application/pdf"
        );
    }

    #[test]
    fn an_attachment_part_declares_everything_a_client_needs() {
        let part = Attachment::new("certificate.pdf", b"%PDF-1.7 fake".to_vec()).to_part();
        assert!(part.contains("Content-Type: application/pdf\r\n"));
        assert!(part.contains("Content-Transfer-Encoding: base64\r\n"));
        assert!(part.contains("Content-Disposition: attachment; filename=\"certificate.pdf\"\r\n"));
        // Headers, blank line, then the encoded bytes.
        let (_, body) = part.split_once("\r\n\r\n").expect("a blank line separates them");
        assert_eq!(body.trim_end(), base64_wrapped(b"%PDF-1.7 fake"));
    }

    #[test]
    fn a_multipart_body_opens_and_closes_its_boundary() {
        let (content_type, body) = multipart("mixed", &[text_part("plain", "hi"), text_part("html", "<b>hi</b>")]);
        assert!(content_type.starts_with("multipart/mixed; boundary=\"=_mb_"));
        let b = content_type
            .split("boundary=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("the boundary is in the header");
        assert_eq!(body.matches(&format!("--{b}\r\n")).count(), 2, "one opener per part");
        assert!(body.ends_with(&format!("--{b}--\r\n")), "the closing boundary has trailing dashes");
        assert!(!body.contains(&format!("\r\n{b}\r\n")), "a boundary line always begins with --");
    }
}
