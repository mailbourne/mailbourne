# Mailbourne

> **A liveable mail server and library.**
>
> Single binary, Rust-native, with a built-in inspector for DNS, DKIM, and
> deliverability.

**Status: brewing, and it runs.** ☕ Early days, but there's a working engine:
sending, receiving, the guided console, SMTP submission (AUTH over STARTTLS),
a built-in ACME certbot, and the inbound SPF/DKIM/DMARC "door" all work today.
Not yet proven in the wild, so treat it as pre-1.0. Published across
[crates.io](https://crates.io/crates/mailbourne),
[npm](https://www.npmjs.com/package/mailbourne), and
[PyPI](https://pypi.org/project/mailbourne/) as it's built.

## What it is

- **A console you just run.** No subcommand — bare `mailbourne` opens a
  guided home of your domains, each with a live status, and drilling into one
  shows its health *with the exact records to paste*. `mailbourne serve` runs
  the daemon; `docker run … mailbourne` does it for you.
- **A built-in inspector.** It checks any domain's mail health — MX, SPF,
  DKIM, DMARC, TLS, PTR, blocklists — and teaches as it diagnoses, in plain
  language, never "error 0x2F".
- **A library.** The same engine embeds in Rust apps (`cargo add
  mailbourne`), diagnostics included.

## What it feels like

Run it. Bare `mailbourne` opens the console — your domains at a glance,
framed as encouragement, never blame:

```text
☕ mail.zebflow.com

  *@zebflow.com        send + receive    all sorted ☕
  *@id.zebflow.com     send-only         2 to improve
  ＋ add a domain
  ⚙  server settings
  ↻ refresh
  quit
```

Drill into a domain and you land on its health — with the exact records to
paste right there, no back-and-forth to another screen:

```text
☕ *@id.zebflow.com  ·  send-only
   mail via mail.zebflow.com

   HEALTH   (paste anything marked ⚠ at your DNS provider)
   ✓ SPF     sorted
   ⚠ DKIM    not published yet — paste this:
        mb2026._domainkey.id.zebflow.com   TXT   v=DKIM1; k=rsa; p=MIIB…
   ⚠ DMARC   not published yet — paste this:
        _dmarc.id.zebflow.com   TXT   v=DMARC1; p=none; rua=mailto:you@…

   2 to improve
```

Add a domain, rotate its DKIM key, change what it does, send a test — all
from the same guided menus, each ending by showing you exactly what changed.

## Quickstart

Install the binary, or embed the library:

```bash
cargo install mailbourne                 # the CLI (one static binary)
cargo add mailbourne                      # or embed the engine in a Rust app
# docker: docker run -p 25:25 -v $PWD:/var/mailbourne ghcr.io/mailbourne/mailbourne
```

Then stand a server up. Every step below is a plain, non-interactive command —
the console is just a friendly face over these, so **you type the same things a
script or an agent would**; nothing here needs the menus:

```bash
# one server, one domain that both sends and receives
printf '[server]\nhostname = "mail.example.com"\n' > mailbourne.toml
mailbourne domain  add example.com --mode both        # mints a DKIM key, prints the record to publish
mailbourne account add you@example.com --password '…'  # a real mailbox + submission login
mailbourne server  show                               # the door, TLS, submission, limits — at a glance

# publish the DNS records it printed, then have it grade them against what's live:
mailbourne domain show example.com

# a real TLS certificate (mailbourne's own certbot), point the server at it, run:
sudo mailbourne cert obtain --domain mail.example.com --production
mailbourne server set --tls-cert mail.example.com.crt --tls-key mail.example.com.key
sudo mailbourne serve --port 25
```

Two chores live at your VPS provider, not here: set the server's **PTR**
(reverse DNS) and confirm outbound **port 25** isn't blocked. The inspector
flags both if they're wrong.

## Every command

The interactive console can do all of this, but each action is also a
first-class command — so a person and a script reach for exactly the same
thing. Add `--config <path>` to point at a specific `mailbourne.toml`.

| To… | Run |
|---|---|
| send one message, narrating each step | `mailbourne send --to … --from …` |
| run the receiving daemon | `mailbourne serve --port 25` |
| add a domain (mints its DKIM key) | `mailbourne domain add <name> --mode out\|in\|both` |
| change a domain's direction | `mailbourne domain set-mode <name> --mode …` |
| rotate a domain's DKIM key | `mailbourne domain rekey <name> --selector …` |
| drop a domain | `mailbourne domain remove <name>` |
| grade a domain against live DNS | `mailbourne domain show <name>` |
| list domains | `mailbourne domain list` |
| add a mailbox (and submission login) | `mailbourne account add <addr> --password …` |
| change a password / remove an account | `mailbourne account passwd\|remove <addr>` |
| view or change server settings | `mailbourne server show` · `mailbourne server set --…` |
| forward an address elsewhere | `mailbourne forward add <alias> --to <dest>` |
| mint a DKIM key + print its record | `mailbourne dns keygen --selector … --domain …` |
| get a TLS cert from Let's Encrypt | `mailbourne cert obtain --domain … [--production]` |
| explain a piece of jargon | `mailbourne explain <term>` |

Pass `--password` to `account add`/`passwd` to run unattended; omit it for a
hidden prompt. Config edits preserve your comments and layout.

## The map of email (and where it trips people up)

Self-hosting email isn't hard because any one step is hard. It's hard
because the settings are **scattered across four places**, and nobody tells
you which mistake in which place is the one silently sending you to spam.
Here's the whole landscape — and what mailbourne does about each piece.

**The four places your setup actually lives:**

| Place | What's there | Mailbourne's job |
|---|---|---|
| `mailbourne.toml` | your settings: hostname, domains, modes, key paths | the one file **you** edit |
| DNS (Cloudflare, etc.) | the public records: MX, SPF, DKIM, DMARC | **generates** them for you, **inspects** what's live |
| server disk | the secrets: DKIM keys, TLS cert, the queue | **manages** it — you never touch it |
| your VPS provider | PTR (reverse DNS), port-25 unblock | **detects** the gap, hands you the exact fix |

The goal: you hand-edit **one** config file. DNS is generated for you, disk
is managed for you, and the two provider chores get flagged with the exact
thing to click.

**The six kinds of thing a mail setup needs** — most people only know two
(auth and encryption) and get ambushed by the rest:

| Kind | The question it answers | Matters most for |
|---|---|---|
| **Identity** | who am I? (hostname, IP, domain names) | both |
| **Reachability** | can we connect? (port 25, PTR) | both |
| **Authentication** | is this mail really from you? (SPF, DKIM, DMARC) | **sending** |
| **Transport** | is it encrypted, is the server real? (TLS cert) | **receiving** |
| **Routing** | where does mail go? (MX, listeners) | **receiving** |
| **Accounts** | who has mailboxes? (users, aliases) | receiving only |

…plus one you can't set at all — **reputation** (do others trust your IP?).
That's earned through careful sending, not configured. It's why a perfectly
authenticated first email still lands in spam, and why no tool can promise
the inbox on day one. Mailbourne's honesty about this is the point:
authentication is engineering (we nail it); reputation is patience (we
show you the truth).

**The things that quietly get people wrong** — every one of these is a check
the inspector is built to catch:

- a placeholder pasted verbatim into a DNS record (`ip4:VPS_IP`)
- **two** SPF records where only one is allowed (silent permanent failure)
- a DKIM key on disk that no longer matches the one published in DNS
- a Cloudflare-proxied ("orange cloud") mail host — looks fine, kills SMTP
- outbound port 25 blocked by the VPS provider
- a missing PTR record dragging you into spam
- accidentally replacing your existing inbox's MX while adding a new domain

**What you actually do**, once mailbourne is handling the rest:

1. edit `mailbourne.toml` — hostname, and each domain with its mode
2. paste the DNS records mailbourne prints, into your provider
3. two one-time provider chores: set PTR, confirm port 25
4. *(for receiving)* `mailbourne domain add` handles the mailboxes

**Modes keep your existing setup safe.** Each domain declares `out`, `in`,
or `both` — and the default, `out`, means mailbourne **never touches your
MX**. Send through mailbourne while your inbox stays on Gmail or Cloudflare,
with zero risk of breaking it. One server can carry many domains this way —
`hello@one.com` and `hello@another.org`, each its own letterhead, all on
one quiet engine.

## What this will not be

A groupware suite. Projects like mailcow and docker-mailserver are excellent
at that — this is just a quiet, single-origin cup of email.

## License

MIT OR Apache-2.0, at your option.
