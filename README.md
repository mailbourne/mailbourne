# Mailbourne

> **A liveable mail server and library.**
>
> Single binary, Rust-native, with a built-in inspector for DNS, DKIM, and
> deliverability.

**Status: brewing.** ☕ Early days — outbound sending and the guided console
work today; receiving and the full daemon are in progress. Published across
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
For scripting, every action has a plain subcommand too (`mailbourne domain
add`, `mailbourne send`, …).

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
