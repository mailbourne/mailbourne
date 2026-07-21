# Architecture — start here

mailbourne is a Cargo workspace where each crate has one job, and the folder
tree reads like the journey of an email. Read in this order:

| Crate | One job | Read it to learn |
|---|---|---|
| `mailbourne-core` | **The vocabulary.** The nouns every other crate shares: addresses, envelopes, messages, events, config. | What an email *is* (envelope vs letter — the distinction everything else builds on). |
| `mailbourne-probe` | **Questions we ask the world.** Read-only checks: DNS lookups, port dials, TLS handshakes, blocklists. Every probe returns typed evidence. | How the outside world sees a mail server. |
| `mailbourne-out` | **A message must leave.** The outbound journey in six numbered steps: sign → route → dial → conversation → queue → retry. | How email actually travels. Read `src/lib.rs` first — the modules are the tutorial. |
| `mailbourne-doctor` | **The judge.** Turns probe evidence into a checklist report (WHAT/WHY/DO/VERIFY/LEARN per item). Returns data; renders nothing. | Why setup fails and how each fix is verified. |
| `mailbourne` | **The face.** The unified library interface (`Mailbourne::builder()`) and the thin CLI over it. | How everything composes. |

Two laws hold everywhere:

1. **Engines return data, renderers render.** `mailbourne-doctor` and
   `mailbourne-probe` have zero terminal/UI dependencies — enforced by the
   dependency graph, not convention.
2. **Files are journey steps, not patterns.** No `utils.rs`, no `manager.rs`.
   If you can't name a file after what happens to the message inside it, the
   boundary is wrong.

Rustdoc is the book: `cargo doc --open` and start at `mailbourne-out`.
