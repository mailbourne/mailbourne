# Architecture — start here

mailbourne is **one crate**, one published package, one binary. The module
tree *is* the shape of the thing: one top-level group per case, plus an
always-on foundation and the built-in inspector. Each group maps to a cargo
feature, so the folders and the compile-time surface line up.

```
src/
  shared/    always    vocabulary, DKIM keys, compose, identity — reusable by all
  inspect/   always    the built-in inspector: probe → judge → sheet
  send/      send       the outbound engine
  server/    server     receive · spool · deliver   (implies send)
  cli/       cli        the operator console          (the default)
```

Embed a lean library with `default-features = false, features = ["server"]`.

| Group | Feature | One job |
|---|---|---|
| `shared/core` | *always* | **The vocabulary.** Addresses, envelopes, messages, events, config — the nouns every group shares. |
| `shared/dkim` | *always* | **Keys, not signatures.** Mint a keypair; derive its publishable `v=DKIM1;…` record. Pure RSA, no network. |
| `shared/{compose,identity}` | *always* | Build a well-formed message; resolve a domain's signing identity from config. |
| `inspect/` | *always* | **The built-in inspector.** Ask the world (`probe`: DNS, TLS, blocklists), judge it (`checklist`, `sheet`), render nothing. |
| `send/` | `send` | **A message must leave.** Sign → route → dial → conversation → queue → retry. Read `send/mod.rs` first. |
| `server/inbound` | `server` | **A message must arrive.** The server side of SMTP: greet, accept (or refuse), collect DATA, commit before `250`. |
| `server/{policy,store,spool}` | `server` | **Accept, keep, deliver.** Never an open relay; Maildir; the durable queue that makes a `250` a promise. |
| `server/{route,serve,worker}` | `server` | **The daemon.** Delivery targets (including `FnTarget` for embedding apps), the acceptor, the async worker. |
| `cli/` | `cli` | **The face.** The interactive console and the CLI over everything. |

Three laws hold everywhere:

1. **The tree is the design.** A top-level group is a case (`send`/`server`/
   `cli`) or the always-on foundation (`shared`/`inspect`). Nothing in
   `shared` or `inspect` imports upward into a case.
2. **Engines return data, renderers render.** `inspect` has zero terminal/UI
   dependencies — enforced by the module graph, not convention.
3. **Files are journey steps, not patterns.** No `utils.rs`, no `manager.rs`.
   If you can't name a file after what happens to the message inside it, the
   boundary is wrong.

Rustdoc is the book: `cargo doc --open` and start at `send`.
