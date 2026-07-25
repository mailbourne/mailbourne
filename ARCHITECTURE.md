# Architecture — start here

mailbourne is **one crate**, one published package, one binary. Inside it,
each module has one job, and the module tree reads like the journey of an
email. (It began as a workspace of `mailbourne-*` crates; those are now
modules — same boundaries, one thing to install and publish.) Read in this
order:

| Module | One job | Read it to learn |
|---|---|---|
| `core` | **The vocabulary.** The nouns every other module shares: addresses, envelopes, messages, events, config. | What an email *is* (envelope vs letter — the distinction everything else builds on). |
| `probe` | **Questions we ask the world.** Read-only checks: DNS lookups, port dials, TLS handshakes, blocklists. Every probe returns typed evidence. | How the outside world sees a mail server. |
| `out` | **A message must leave.** The outbound journey in numbered steps: sign → route → dial → conversation → queue → retry. | How email actually travels. Read `out/mod.rs` first — the modules are the tutorial. |
| `inbound` | **A message must arrive.** The server side of SMTP: greet, accept (or refuse) recipients, collect DATA, commit before `250`. | How receiving mirrors sending. |
| `policy` / `store` / `spool` | **Accept, keep, deliver.** Who we accept mail for (never an open relay), where it lands (Maildir), and the durable queue that guarantees an accepted message is never lost. | How a `250` becomes a promise. |
| `checklist` | **The judge.** Turns probe evidence into a checklist report (WHAT/WHY/DO/VERIFY/LEARN per item). Returns data; renders nothing. | Why setup fails and how each fix is verified. |
| `route`, `serve`, `worker` + the crate root | **The face.** Delivery targets (including `FnTarget` for embedding apps), the daemon, the async delivery worker, and the CLI over it all. | How everything composes. |

Two laws hold everywhere:

1. **Engines return data, renderers render.** `checklist` and `probe` have
   zero terminal/UI dependencies — enforced by the module graph, not
   convention.
2. **Files are journey steps, not patterns.** No `utils.rs`, no `manager.rs`.
   If you can't name a file after what happens to the message inside it, the
   boundary is wrong.

Rustdoc is the book: `cargo doc --open` and start at `out`.
