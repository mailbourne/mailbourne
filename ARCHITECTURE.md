# Architecture — start here

mailbourne is **one crate**, one published package, one binary. Inside it,
each module has one job, and the module tree reads like the journey of an
email. (It began as a workspace of `mailbourne-*` crates; those are now
modules — same boundaries, one thing to install and publish.) Read in this
order:

Three things are **always present** — the vocabulary, DKIM key management, and
the built-in inspector — because they're part of what mailbourne *is*.
Everything else is a cargo feature: `send` (outbound engine), `server`
(receive + spool + deliver, implies `send`), and `cli` (the binary + console,
the default). Embed a lean library with
`default-features = false, features = ["server"]`.

| Module | Feature | One job |
|---|---|---|
| `core` | *always* | **The vocabulary.** The nouns every module shares: addresses, envelopes, messages, events, config. |
| `dkim` | *always* | **Keys, not signatures.** Mint a keypair; derive its publishable `v=DKIM1;…` record. Pure RSA, no network. |
| `probe` / `checklist` / `inspect` / `sheet` | *always* | **The built-in inspector.** Ask the world (DNS, TLS, blocklists), judge the evidence into a checklist, render nothing. |
| `out` | `send` | **A message must leave.** Sign → route → dial → conversation → queue → retry. Read `out/mod.rs` first. |
| `inbound` | `server` | **A message must arrive.** The server side of SMTP: greet, accept (or refuse), collect DATA, commit before `250`. |
| `policy` / `store` / `spool` | `server` | **Accept, keep, deliver.** Never an open relay; Maildir; the durable queue that makes a `250` a promise. |
| `route`, `serve`, `worker` | `server` | **The daemon.** Delivery targets (including `FnTarget` for embedding apps), the acceptor, the async worker. |
| `console` + crate root | `cli` | **The face.** The interactive console and the CLI over everything. |

Two laws hold everywhere:

1. **Engines return data, renderers render.** `checklist` and `probe` have
   zero terminal/UI dependencies — enforced by the module graph, not
   convention.
2. **Files are journey steps, not patterns.** No `utils.rs`, no `manager.rs`.
   If you can't name a file after what happens to the message inside it, the
   boundary is wrong.

Rustdoc is the book: `cargo doc --open` and start at `out`.
