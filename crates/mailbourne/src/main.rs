//! The `mailbourne` command line — a thin shell over the library.
//!
//! Today it carries the Milestone 0 proof tool: `mailbourne send`, which
//! walks one message through the whole outbound journey and narrates every
//! step. The full engine (the console, `serve`, `inspect`, `learn`)
//! arrives next.

use clap::{Parser, Subcommand};
use mailbourne::send::conversation::Outcome;
use mailbourne::{EmailAddress, Envelope};

#[derive(Parser)]
#[command(
    name = "mailbourne",
    version,
    about = "A liveable mail server and library"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
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
    /// Run the receiving server (the daemon; docker's default command).
    Serve {
        /// Address to bind.
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        /// Port to listen on (25 is the real MX port; needs privilege).
        #[arg(long, default_value_t = 25)]
        port: u16,
        /// Where to store received mail (a Maildir root).
        #[arg(long, default_value = "mail")]
        store: std::path::PathBuf,
        /// Path to mailbourne.toml (same search as `send`).
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
    /// Manage mailbox accounts (real addresses + passwords).
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Explain a mail abbreviation in plain words (STARTTLS, DKIM, SPF, …).
    Explain {
        /// The term to explain. Omit to list every term.
        term: Option<String>,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Add a mailbox account, prompting for its password.
    Add {
        /// The full address, e.g. bob@ours.com.
        address: String,
        /// Storage quota in MiB (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        quota_mb: u64,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// List the mailbox accounts, one line each.
    List {
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
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
    let code = match cli.command {
        // Bare `mailbourne` (a human, no subcommand) → the console.
        // Called from the main thread, so the console may `handle.block_on`.
        None => mailbourne::cli::console::run(runtime.handle(), None),
        Some(command) => runtime.block_on(run_command(command)),
    };
    std::process::exit(code);
}

async fn run_command(command: Command) -> i32 {
    match command {
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
            let overrides = mailbourne::shared::identity::Overrides {
                hostname,
                dkim_domain,
                dkim_selector,
                dkim_key,
            };
            let id = mailbourne::shared::identity::resolve(config.as_ref(), &from, &overrides);
            for note in &id.notes {
                println!("  · {note}");
            }
            let hostname = id.hostname;

            println!("  building message (RFC 5322)…… ✓");
            let mut message =
                mailbourne::shared::compose::plain_text(&from, &to, &subject, &body, &hostname);

            match &id.dkim {
                Some(dkim) => {
                    let pem = match std::fs::read_to_string(&dkim.key_path) {
                        Ok(pem) => pem,
                        Err(e) => {
                            eprintln!("✗ could not read {}: {e}", dkim.key_path.display());
                            return 2;
                        }
                    };
                    match mailbourne::send::sign::dkim_sign(
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
                    mailbourne::send::send_to_host(&h, p, &hostname, &envelope, &message).await
                }
                None => {
                    println!("  MX routing {}…", to.domain());
                    mailbourne::send::send(&hostname, &envelope, &message).await
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
        Command::Serve {
            bind,
            port,
            store,
            config,
        } => serve_cmd(&bind, port, &store, config.as_deref()).await,
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
        Command::Account { command } => account_cmd(command),
        Command::Explain { term } => explain_cmd(term.as_deref()),
    }
}

/// `mailbourne explain [term]` — plain words for the jargon.
fn explain_cmd(term: Option<&str>) -> i32 {
    use mailbourne::shared::glossary;
    match term {
        Some(term) => match glossary::describe(term) {
            Some(entry) => {
                println!("  {} · {}", entry.abbr, entry.full);
                println!("  {}", entry.plain);
                println!("  learn more → {}", glossary::learn_more(entry.abbr));
                0
            }
            None => {
                eprintln!("✗ no glossary entry for \"{term}\".");
                eprintln!("  run `mailbourne explain` to see everything I can describe.");
                2
            }
        },
        None => {
            println!("mail is full of abbreviations — here's what each means:\n");
            for entry in glossary::all() {
                println!("  {:<9} {}", entry.abbr, entry.full);
            }
            println!("\nexplain any of them: mailbourne explain <term>");
            0
        }
    }
}

/// Resolves the path of an existing config (same search as `load_config`),
/// or `None` if there isn't one to edit.
fn existing_config_path(flag: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    if let Some(p) = flag {
        return p.exists().then(|| p.to_path_buf());
    }
    if let Some(env) = std::env::var_os("MAILBOURNE_CONFIG") {
        let p = std::path::PathBuf::from(env);
        return p.exists().then_some(p);
    }
    ["mailbourne.toml", "/var/mailbourne/mailbourne.toml"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
}

/// `mailbourne account add|list`.
fn account_cmd(command: AccountCommand) -> i32 {
    match command {
        AccountCommand::Add {
            address,
            quota_mb,
            config,
        } => {
            if EmailAddress::parse(&address).is_err() {
                eprintln!("✗ an account address must look like someone@somewhere.tld");
                return 2;
            }
            let Some(path) = existing_config_path(config.as_deref()) else {
                eprintln!(
                    "✗ no mailbourne.toml found — register a domain first, then add accounts."
                );
                return 2;
            };
            let password = match dialoguer::Password::new()
                .with_prompt(format!("Password for {address}"))
                .with_confirmation("Confirm password", "passwords don't match")
                .interact()
            {
                Ok(password) => password,
                Err(_) => return 1,
            };
            let hash = match mailbourne::server::accounts::hash_password(&password) {
                Ok(hash) => hash,
                Err(e) => {
                    eprintln!("✗ {e}");
                    return 1;
                }
            };
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("✗ couldn't read {}: {e}", path.display());
                    return 1;
                }
            };
            let updated = match mailbourne::shared::core::edit::add_account(
                &text,
                &address,
                &hash,
                quota_mb * 1024 * 1024,
            ) {
                Ok(updated) => updated,
                Err(e) => {
                    eprintln!("✗ {e}");
                    return 2;
                }
            };
            if let Err(e) = std::fs::write(&path, updated) {
                eprintln!("✗ couldn't write {}: {e}", path.display());
                return 1;
            }
            println!("✓ account {address} added to {}", path.display());
            println!("  it can receive mail now; once AUTH lands it can send through this server.");
            0
        }
        AccountCommand::List { config } => {
            let cfg = match require_config(config.as_deref()) {
                Ok(cfg) => cfg,
                Err(code) => return code,
            };
            if cfg.accounts.is_empty() {
                println!("no accounts yet — add one: mailbourne account add <address>");
            } else {
                for a in &cfg.accounts {
                    let quota = if a.quota_bytes > 0 {
                        format!("{} MiB", a.quota_bytes / (1024 * 1024))
                    } else {
                        "unlimited".to_string()
                    };
                    let status = if a.enabled { "" } else { "  (disabled)" };
                    println!("  {}   quota {quota}{status}", a.address);
                }
            }
            0
        }
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

    let pair = match mailbourne::shared::dkim::generate_dkim_keypair() {
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

/// `mailbourne domain show <name>` — the sheet, judged live. Shares its
/// gathering and rendering with the console (see `inspect` + `sheet::render`).
async fn domain_show(name: &str, config_flag: Option<&std::path::Path>) -> i32 {
    let config = match require_config(config_flag) {
        Ok(config) => config,
        Err(code) => return code,
    };

    println!("  asking DNS how the world sees {name} right now…");
    let Some((sheet, ip)) = mailbourne::inspect::domain(&config, name).await else {
        eprintln!("✗ {name} isn't in the registry — adopt it with: mailbourne domain add {name}");
        return 2;
    };

    let rendered = mailbourne::inspect::sheet::render(&sheet, name, &config.server.hostname, ip);
    println!("\n{}", rendered.text);
    if rendered.to_do == 0 {
        println!("  lovely — nothing to paste; {name} is all sorted. ☕");
    } else {
        println!(
            "  {} to paste · re-run me after DNS settles (usually minutes)",
            rendered.to_do
        );
    }
    0
}

/// `mailbourne serve` — run the receiving daemon.
async fn serve_cmd(
    bind: &str,
    port: u16,
    store_path: &std::path::Path,
    config_flag: Option<&std::path::Path>,
) -> i32 {
    let config = match require_config(config_flag) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let addr: std::net::SocketAddr = match format!("{bind}:{port}").parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("✗ {bind}:{port} isn't a valid address to bind.");
            return 2;
        }
    };
    let store = mailbourne::server::store::Maildir::at(store_path);

    // Receive only for domains registered in / both — never an open relay.
    let hosted: Vec<String> = config
        .domains
        .iter()
        .filter(|d| {
            matches!(
                d.mode,
                mailbourne::config::Mode::In | mailbourne::config::Mode::Both
            )
        })
        .map(|d| d.name.clone())
        .collect();
    // Acceptance knows our mailboxes: hosted domains + real accounts + forward
    // aliases. A hosted domain with no accounts stays a catch-all.
    let accounts = mailbourne::server::accounts::Accounts::from_config(&config.accounts);
    // The same registry authenticates SMTP AUTH logins (offered only over TLS).
    let auth: Option<std::sync::Arc<dyn mailbourne::server::inbound::session::Authenticator>> =
        if accounts.is_empty() {
            None
        } else {
            Some(std::sync::Arc::new(accounts.clone()))
        };
    let forward_matches = config.forwards.iter().map(|f| f.match_recipient.clone());
    let policy: std::sync::Arc<dyn mailbourne::server::policy::Policy> = std::sync::Arc::new(
        mailbourne::server::policy::Acceptance::new(hosted.clone(), accounts, forward_matches),
    );

    // Every accepted message is stored; if a webhook is configured, it's also
    // announced by HTTP POST (retried through the spool). Forward / queue join
    // this list as routing grows.
    let mut target_list: Vec<std::sync::Arc<dyn mailbourne::server::route::DeliveryTarget>> =
        vec![std::sync::Arc::new(
            mailbourne::server::route::MailboxTarget::new(store.clone()),
        )];
    if let Some(url) = &config.server.webhook_url {
        target_list.push(std::sync::Arc::new(
            mailbourne::server::webhook::WebhookTarget::new(url.clone()),
        ));
    }
    if !config.forwards.is_empty() {
        let rules = config
            .forwards
            .iter()
            .map(|r| (r.match_recipient.clone(), r.to.clone()));
        target_list.push(std::sync::Arc::new(
            mailbourne::server::forward::ForwardTarget::new(config.server.hostname.clone(), rules),
        ));
    }
    // Submission: an authenticated client's mail is DKIM-signed and relayed
    // to the world through this target (never reached by incoming mail).
    target_list.push(std::sync::Arc::new(
        mailbourne::server::outbound::OutboundTarget::new(config.clone()),
    ));
    let targets: mailbourne::server::serve::Targets = std::sync::Arc::new(target_list);

    println!(
        "☕ mailbourne — serving {} on {addr}",
        config.server.hostname
    );
    println!("   received mail → {}", store_path.display());
    if let Some(url) = &config.server.webhook_url {
        println!("   webhook → {url}");
    }
    for rule in &config.forwards {
        println!("   forward {} → {}", rule.match_recipient, rule.to);
    }
    if !config.accounts.is_empty() {
        println!(
            "   submission → {} account(s) may send through this server (AUTH over TLS)",
            config.accounts.len()
        );
    }
    if config.server.mailbox_quota_bytes > 0 {
        println!(
            "   mailbox quota → {} MiB",
            config.server.mailbox_quota_bytes / (1024 * 1024)
        );
    }
    if hosted.is_empty() {
        println!("   ⚠ no domains registered to receive (mode in/both) — every recipient");
        println!("     will be refused. add one: mailbourne domain add <name>");
    } else {
        println!("   receiving for: {}", hosted.join(", "));
    }
    if port == 25 {
        println!(
            "   (port 25 needs privilege — run with sudo or a cap, or use --port 2525 to try it)"
        );
    }
    // STARTTLS: a real certificate when configured (needed for clients like
    // Gmail that verify it), otherwise a self-signed one so encryption still
    // works out of the box.
    let tls = match (&config.server.tls_cert, &config.server.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            match (
                std::fs::read_to_string(cert_path),
                std::fs::read_to_string(key_path),
            ) {
                (Ok(cert), Ok(key)) => {
                    match mailbourne::server::tls::acceptor_from_pem(&cert, &key) {
                        Ok(acceptor) => {
                            println!("   STARTTLS → on (cert {})", cert_path.display());
                            Some(std::sync::Arc::new(acceptor))
                        }
                        Err(e) => {
                            eprintln!("   ⚠ STARTTLS off — cert/key didn't load: {e}");
                            None
                        }
                    }
                }
                _ => {
                    eprintln!("   ⚠ STARTTLS off — couldn't read the cert/key files");
                    None
                }
            }
        }
        _ => match mailbourne::server::tls::self_signed(&config.server.hostname) {
            Ok(acceptor) => {
                println!("   STARTTLS → on (self-signed; set tls_cert/tls_key for a real one)");
                Some(std::sync::Arc::new(acceptor))
            }
            Err(_) => None,
        },
    };

    // Accepted-but-not-yet-delivered mail lives in a spool beside the maildir.
    let spool_dir = store_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("spool");
    match mailbourne::server::serve::run(
        addr,
        config.server.hostname.clone(),
        policy,
        targets,
        spool_dir,
        config.server.spool_max_bytes,
        store,
        config.server.mailbox_quota_bytes,
        tls,
        auth,
    )
    .await
    {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("✗ couldn't serve on {addr}: {e}");
            1
        }
    }
}
