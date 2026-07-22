//! The `mailbourne` command line — a thin shell over the library.
//!
//! Today it carries the Milestone 0 proof tool: `mailbourne send`, which
//! walks one message through the whole outbound journey and narrates every
//! step. The full engine (`run`, `inspect`, `dns`, `learn`) arrives next.

use clap::{Parser, Subcommand};
use mailbourne::out::conversation::Outcome;
use mailbourne::{EmailAddress, Envelope};

#[derive(Parser)]
#[command(
    name = "mailbourne",
    version,
    about = "A liveable mail server and library"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send one email through the outbound engine, narrating each step.
    Send {
        /// Recipient address (where the letter goes).
        #[arg(long)]
        to: String,
        /// Sender address (the envelope AND the From: header).
        #[arg(long)]
        from: String,
        /// Subject line.
        #[arg(long, default_value = "mailbourne proof of life ☕")]
        subject: String,
        /// Plain-text body.
        #[arg(
            long,
            default_value = "This message left through mailbourne's own engine."
        )]
        body: String,
        /// Our HELO identity; defaults to mail.<sender-domain>.
        #[arg(long)]
        hostname: Option<String>,
        /// DKIM: signing domain (defaults to the sender's domain).
        #[arg(long)]
        dkim_domain: Option<String>,
        /// DKIM: selector (the name before ._domainkey in DNS).
        #[arg(long)]
        dkim_selector: Option<String>,
        /// DKIM: path to the RSA private key (PKCS#1 PEM).
        #[arg(long)]
        dkim_key: Option<std::path::PathBuf>,
        /// Skip MX routing and dial this host directly (host or host:port).
        #[arg(long)]
        host: Option<String>,
        /// Path to mailbourne.toml (default: $MAILBOURNE_CONFIG, then
        /// ./mailbourne.toml, then /var/mailbourne/mailbourne.toml).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// DNS toolbox: mint keys and print the records to publish.
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
    /// Manage the domains this server sends and receives for.
    Domain {
        #[command(subcommand)]
        command: DomainCommand,
    },
}

#[derive(Subcommand)]
enum DomainCommand {
    /// The record sheet for one domain: what to paste, judged against
    /// what's actually published right now.
    Show {
        /// The domain (must be in the registry).
        name: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Every managed domain, one line each.
    List {
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum DnsCommand {
    /// Mint a fresh 2048-bit DKIM keypair and print the record to publish.
    Keygen {
        /// Selector — the name before `._domainkey` in DNS.
        #[arg(long, default_value = "mb2026")]
        selector: String,
        /// Your mail domain (used only to print the exact DNS names).
        #[arg(long)]
        domain: Option<String>,
        /// Where to write the private key.
        #[arg(long, default_value = "dkim.pem")]
        out: std::path::PathBuf,
        /// Overwrite an existing key file. Dangerous: a replaced key
        /// invalidates the record currently in DNS.
        #[arg(long)]
        force: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = runtime.block_on(run(cli));
    std::process::exit(code);
}

async fn run(cli: Cli) -> i32 {
    match cli.command {
        Command::Send {
            to,
            from,
            subject,
            body,
            hostname,
            dkim_domain,
            dkim_selector,
            dkim_key,
            host,
            config,
        } => {
            let (Ok(from), Ok(to)) = (EmailAddress::parse(&from), EmailAddress::parse(&to)) else {
                eprintln!("✗ addresses must look like someone@somewhere.tld");
                return 2;
            };

            let config = match load_config(config.as_deref()) {
                Ok(config) => config,
                Err(code) => return code,
            };
            let overrides = mailbourne::identity::Overrides {
                hostname,
                dkim_domain,
                dkim_selector,
                dkim_key,
            };
            let id = mailbourne::identity::resolve(config.as_ref(), &from, &overrides);
            for note in &id.notes {
                println!("  · {note}");
            }
            let hostname = id.hostname;

            println!("  building message (RFC 5322)…… ✓");
            let mut message =
                mailbourne::compose::plain_text(&from, &to, &subject, &body, &hostname);

            match &id.dkim {
                Some(dkim) => {
                    let pem = match std::fs::read_to_string(&dkim.key_path) {
                        Ok(pem) => pem,
                        Err(e) => {
                            eprintln!("✗ could not read {}: {e}", dkim.key_path.display());
                            return 2;
                        }
                    };
                    match mailbourne::out::sign::dkim_sign(
                        &message,
                        &dkim.domain,
                        &dkim.selector,
                        &pem,
                    ) {
                        Ok(signed) => {
                            println!("  DKIM signing ({})……… ✓  d={}", dkim.selector, dkim.domain);
                            message = signed;
                        }
                        Err(e) => {
                            eprintln!("✗ refusing to send unsigned: {e}");
                            return 2;
                        }
                    }
                }
                None => println!("  DKIM signing………………… — skipped (no key via flags or registry)"),
            }

            let envelope = Envelope {
                mail_from: from,
                rcpt_to: vec![to.clone()],
            };

            let result = match host {
                Some(direct) => {
                    let (h, p) = match direct.rsplit_once(':') {
                        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(25)),
                        None => (direct, 25),
                    };
                    println!("  dialing {h}:{p} directly (MX routing skipped)…");
                    mailbourne::out::send_to_host(&h, p, &hostname, &envelope, &message).await
                }
                None => {
                    println!("  MX routing {}…", to.domain());
                    mailbourne::out::send(&hostname, &envelope, &message).await
                }
            };

            match result {
                Ok(Outcome::Delivered { reply }) => {
                    println!("  → {} {}", reply.code, reply.lines.join(" / "));
                    println!("\n★ ACCEPTED — responsibility has transferred.");
                    println!("  Open the inbox and check \"show original\" for SPF/DKIM/DMARC.");
                    0
                }
                Ok(Outcome::Deferred { at, reply }) => {
                    println!(
                        "\n⏳ DEFERRED at {at:?}: {} {}",
                        reply.code,
                        reply.lines.join(" / ")
                    );
                    println!(
                        "  \"Not now\" — a real queue would retry with backoff (greylisting?)."
                    );
                    1
                }
                Ok(Outcome::Rejected { at, reply }) => {
                    println!(
                        "\n✗ REJECTED at {at:?}: {} {}",
                        reply.code,
                        reply.lines.join(" / ")
                    );
                    1
                }
                Err(e) => {
                    eprintln!("\n✗ {e}");
                    1
                }
            }
        }
        Command::Domain { command } => match command {
            DomainCommand::Show { name, config } => domain_show(&name, config.as_deref()).await,
            DomainCommand::List { config } => domain_list(config.as_deref()),
        },
        Command::Dns { command } => match command {
            DnsCommand::Keygen {
                selector,
                domain,
                out,
                force,
            } => keygen(&selector, domain.as_deref(), &out, force),
        },
    }
}

/// Mint a DKIM keypair: write the secret half, print the public half.
fn keygen(selector: &str, domain: Option<&str>, out: &std::path::Path, force: bool) -> i32 {
    if out.exists() && !force {
        eprintln!(
            "✗ {} already exists — refusing to overwrite.",
            out.display()
        );
        eprintln!("  A replaced key silently invalidates the record already in");
        eprintln!("  DNS (mail keeps signing, verification starts failing).");
        eprintln!("  If you really mean to rotate: --force, then re-publish the");
        eprintln!("  printed record before the next send.");
        return 2;
    }

    let pair = match mailbourne::out::sign::generate_dkim_keypair() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("✗ could not mint a keypair: {e}");
            return 1;
        }
    };

    if let Err(e) = std::fs::write(out, &pair.private_key_pem) {
        eprintln!("✗ could not write {}: {e}", out.display());
        return 1;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600));
    }

    println!(
        "✓ private key written to {}  (mode 600 — it never leaves this machine)",
        out.display()
    );
    println!();
    println!("Publish this TXT record at your DNS provider:");
    println!();
    match domain {
        Some(domain) => {
            println!("  Name:    {selector}._domainkey.{domain}");
            println!("  Type:    TXT");
            println!("  Content: {}", pair.dns_record_value);
            println!();
            println!("  (Cloudflare tip: if your zone is a parent of {domain},");
            println!("   the Name field wants everything left of the zone apex.)");
        }
        None => {
            println!("  Name:    {selector}._domainkey.<your-domain>");
            println!("  Type:    TXT");
            println!("  Content: {}", pair.dns_record_value);
        }
    }
    println!();
    println!("What just happened: DKIM is a wax seal. The secret key stamps every");
    println!("outgoing message; the record above is the public half the world uses");
    println!("to check the stamp. Then:  mailbourne send --dkim-selector {selector} \\");
    println!(
        "  --dkim-key {} --to you@example.com --from proof@<your-domain>",
        out.display()
    );
    0
}

/// Finds and loads `mailbourne.toml`.
///
/// Search order: `--config` flag, `$MAILBOURNE_CONFIG`, `./mailbourne.toml`,
/// `/var/mailbourne/mailbourne.toml` — first hit wins. No config anywhere is
/// fine (flags and conventions carry the send); a config that EXISTS but
/// won't parse is a hard stop — broken configuration must never be
/// silently ignored.
fn load_config(flag: Option<&std::path::Path>) -> Result<Option<mailbourne::config::Config>, i32> {
    let explicit = flag
        .map(std::path::Path::to_path_buf)
        .or_else(|| std::env::var_os("MAILBOURNE_CONFIG").map(Into::into));

    if let Some(path) = explicit {
        // Asked for by name: it must exist and it must parse.
        return match mailbourne::config::Config::load(&path) {
            Ok(config) => {
                println!("  using {}", path.display());
                Ok(Some(config))
            }
            Err(e) => {
                eprintln!("✗ {e}");
                Err(2)
            }
        };
    }

    for candidate in ["mailbourne.toml", "/var/mailbourne/mailbourne.toml"] {
        let path = std::path::Path::new(candidate);
        if path.exists() {
            return match mailbourne::config::Config::load(path) {
                Ok(config) => {
                    println!("  using {}", path.display());
                    Ok(Some(config))
                }
                Err(e) => {
                    eprintln!("✗ your config has a problem — fix it rather than let me guess:");
                    eprintln!("  {e}");
                    Err(2)
                }
            };
        }
    }
    Ok(None)
}

/// Loads the config or explains, in one line, how to get one.
fn require_config(flag: Option<&std::path::Path>) -> Result<mailbourne::config::Config, i32> {
    match load_config(flag)? {
        Some(config) => Ok(config),
        None => {
            eprintln!("✗ no mailbourne.toml found — nothing is registered yet.");
            eprintln!("  start one next to your keys, or point me at it with --config.");
            Err(2)
        }
    }
}

/// `mailbourne domain list` — every letterhead, one line each.
fn domain_list(config_flag: Option<&std::path::Path>) -> i32 {
    let config = match require_config(config_flag) {
        Ok(config) => config,
        Err(code) => return code,
    };
    if config.domains.is_empty() {
        println!("no domains registered yet — adopt one with: mailbourne domain add <name>");
        return 0;
    }
    println!("server: {}", config.server.hostname);
    for domain in &config.domains {
        let mode = match domain.mode {
            mailbourne::config::Mode::Out => "out ",
            mailbourne::config::Mode::In => "in  ",
            mailbourne::config::Mode::Both => "both",
        };
        let key = match &domain.dkim_key {
            Some(path) if path.exists() => "key ✓",
            Some(_) => "key MISSING",
            None => "no key",
        };
        let selector = domain.dkim_selector.as_deref().unwrap_or("—");
        println!(
            "  {:<28} mode {}  selector {:<10} {}",
            domain.name, mode, selector, key
        );
    }
    0
}

/// `mailbourne domain show <name>` — the sheet, judged live.
async fn domain_show(name: &str, config_flag: Option<&std::path::Path>) -> i32 {
    use mailbourne::sheet::{self, RowStatus};

    let config = match require_config(config_flag) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let Some(domain) = config.domain(name) else {
        eprintln!("✗ {name} isn't in the registry — adopt it with: mailbourne domain add {name}");
        return 2;
    };

    println!("  asking DNS how the world sees {name} right now…");
    let selector = domain.dkim_selector.clone();
    let dkim_host = selector
        .as_deref()
        .map(|s| format!("{s}._domainkey.{name}"));

    let domain_txt = mailbourne::probe::dns::txt(name).await.unwrap_or_default();
    let dkim_txt = match &dkim_host {
        Some(host) => mailbourne::probe::dns::txt(host).await.unwrap_or_default(),
        None => Vec::new(),
    };
    let dmarc_txt = mailbourne::probe::dns::txt(&format!("_dmarc.{name}"))
        .await
        .unwrap_or_default();
    let server_ip = mailbourne::probe::dns::a(&config.server.hostname)
        .await
        .unwrap_or_default()
        .first()
        .copied();

    let dkim_record_from_key = domain
        .dkim_key
        .as_deref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|pem| mailbourne::out::sign::public_record_for(&pem).ok());

    let evidence = sheet::Evidence {
        domain_txt,
        dkim_txt,
        dmarc_txt,
        server_ip,
        dkim_record_from_key,
    };
    let sheet = sheet::build(
        name,
        domain.mode,
        selector.as_deref(),
        &config.server.hostname,
        &evidence,
    );

    println!();
    println!(
        "── {name} · server {}{} ──",
        config.server.hostname,
        match server_ip {
            Some(ip) => format!(" ({ip})"),
            None => " (does not resolve!)".to_string(),
        }
    );
    println!();
    let mut to_do = 0;
    for row in &sheet.rows {
        let (glyph, verb) = match &row.status {
            RowStatus::Add => {
                to_do += 1;
                ("+", "ADD")
            }
            RowStatus::AlreadyCorrect => ("✓", "already sorted"),
            RowStatus::Replace { .. } => {
                to_do += 1;
                ("↻", "REPLACE")
            }
            RowStatus::Broken { .. } => {
                to_do += 1;
                ("✗", "NEEDS A DECISION")
            }
        };
        println!("  {glyph} [{verb}]  {}  {}", row.rtype, row.host);
        if let RowStatus::Broken { why } = &row.status {
            println!("      {why}");
        } else if !row.value.is_empty() {
            println!("      {}", row.value);
        }
        if let RowStatus::Replace { current } = &row.status {
            println!("      (currently: {current})");
        }
        println!();
    }
    for note in &sheet.notes {
        println!("  · {note}");
    }
    println!();
    if to_do == 0 {
        println!("  lovely — nothing to paste; {name} is all sorted. ☕");
    } else {
        println!("  {to_do} to paste · re-run me after DNS settles (usually minutes)");
    }
    0
}
