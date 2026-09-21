# Changelog

## 0.0.7 — unreleased

- **`send::conversation::submit`** — submission over a stream that is
  already what it will be: port 465, where TLS starts at the first byte and
  there is no `STARTTLS` to negotiate, or a localhost test sink with no
  encryption at all. The channel is the caller's decision there, and so is
  the risk; `submit_with_starttls` remains the one that refuses to send a
  password in the clear.

## 0.0.6

Rich messages, and the half of SMTP a client speaks.

- **`shared::mime`** — the pieces a message with more than one part is made
  of: boundaries that cannot collide with their content, quoted-printable
  that keeps plain English readable in the raw source, base64 wrapped at 76,
  RFC 2047 headers and RFC 2231 filenames so a subject or an attachment named
  in Indonesian arrives as itself.
- **`compose::rich`** — an HTML rendering beside the text, and files
  alongside. Builds the tree clients expect: `multipart/alternative` for two
  renderings of the same words, wrapped in `multipart/mixed` when files
  travel too. With neither, it is `plain_text` exactly, so the simple case
  pays nothing for the general one.
- **`send::conversation::submit_with_starttls`** — submission, not delivery.
  Mailbourne could deliver between servers but had no way to hand a message
  to a relay that asks who you are, which is what an application needs.
  `AUTH PLAIN`, or `AUTH LOGIN` for relays that only speak that. Unlike
  delivery, TLS is **required**: a relay that does not offer `STARTTLS` is
  refused, because the next thing we would send is a password.
- **`mailbourne send --html` and `--attach`** — `--attach report.pdf` keeps
  the file's name, `--attach "Certificate.pdf=/tmp/c.pdf"` renames it for the
  recipient.

Fixed:

- **A subject is no longer written raw.** It went onto the wire unencoded, so
  any subject outside ASCII produced an invalid header, and a subject
  containing CRLF could inject headers of its own — a `Bcc:`, for instance.
  Both closed by routing it through `mime::header_value`.

## 0.0.1 — unreleased

- Name-reservation skeleton: cargo workspace, registry placeholders (crates.io,
  npm, PyPI), CI stub. The engine is still brewing.
