# Mailbourne

> **A liveable mail server and library.**
>
> Single binary, Rust-native, with a built-in inspector for DNS, DKIM, and
> deliverability.

**Status: brewing.** ☕

Nothing to install yet. The name is reserved across
[crates.io](https://crates.io/crates/mailbourne),
[npm](https://www.npmjs.com/package/mailbourne), and
[PyPI](https://pypi.org/project/mailbourne/) while the engine is built.

## What this will be

- **One binary** that sends, receives, and explains itself — `mailbourne run`
  and the logs talk you through everything still missing, from DKIM records
  to PTR tickets.
- **A built-in inspector** — `mailbourne inspect --domain example.com` probes any
  domain's mail health (MX, SPF, DKIM, DMARC, TLS, PTR, blocklists) and
  teaches as it diagnoses. Works on your existing mail setup, no install.
- **A library** — the same engine embeds in Rust applications
  (`cargo add mailbourne`), diagnostics included.

## What this will not be

A groupware suite. Projects like mailcow and docker-mailserver are excellent
at that — this is just a quiet, single-origin cup of email.

## License

MIT OR Apache-2.0, at your option.
