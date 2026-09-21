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
        /// HTML rendering of the same letter. The plain body stays, as the
        /// fallback for clients that show no HTML.
        #[arg(long)]
        html: Option<String>,
        /// A file to attach. Repeat for several. `--attach report.pdf` keeps
        /// the file's own name; `--attach "Certificate.pdf=/tmp/c.pdf"`
        /// renames it for the recipient.
        #[arg(long = "attach", value_name = "[NAME=]PATH")]
        attach: Vec<String>,
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
    /// Inspect and change server-wide settings (the door, TLS, limits).
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Manage forwarding rules (relay an address on to somewhere else).
    Forward {
        #[command(subcommand)]
        command: ForwardCommand,
    },
    /// Explain a mail abbreviation in plain words (STARTTLS, DKIM, SPF, …).
    Explain {
        /// The term to explain. Omit to list every term.
        term: Option<String>,
    },
    /// Obtain a real TLS certificate from Let's Encrypt (mailbourne's certbot).
    Cert {
        #[command(subcommand)]
        command: CertCommand,
    },
}

#[derive(Subcommand)]
enum CertCommand {
    /// Get a certificate for a domain via the HTTP-01 challenge (needs port 80).
    Obtain {
        /// The domain to certify (the server's hostname, e.g. mb.zebflow.com).
        #[arg(long)]
        domain: String,
        /// Contact email for the CA account (optional but recommended).
        #[arg(long)]
        email: Option<String>,
        /// Use the real Let's Encrypt (trusted). Without this, uses STAGING —
        /// untrusted, but with generous rate limits for testing.
        #[arg(long)]
        production: bool,
        /// Port to answer the HTTP-01 challenge on (Let's Encrypt uses 80).
        #[arg(long, default_value_t = 80)]
        http_port: u16,
        /// Where the long-lived ACME account key lives (created if missing).
        #[arg(long, default_value = "acme-account.pem")]
        account_key: std::path::PathBuf,
        /// Where to write the certificate chain (default: <domain>.crt).
        #[arg(long)]
        out_cert: Option<std::path::PathBuf>,
        /// Where to write the certificate key (default: <domain>.key).
        #[arg(long)]
        out_key: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Add a mailbox account. Pass --password to run unattended (for scripts
    /// and automation); omit it to be prompted interactively.
    Add {
        /// The full address, e.g. bob@ours.com.
        address: String,
        /// The account password. Omit for an interactive, hidden prompt.
        #[arg(long)]
        password: Option<String>,
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
    /// Remove a mailbox account (its stored mail on disk is left alone).
    Remove {
        /// The address to remove.
        address: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Change an account's password. Pass --password to run unattended.
    Passwd {
        /// The address whose password to change.
        address: String,
        /// The new password. Omit for an interactive, hidden prompt.
        #[arg(long)]
        password: Option<String>,
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
    /// Register a new domain: mint its DKIM key and add it to the config.
    Add {
        /// The domain name, e.g. news.example.com.
        name: String,
        /// Direction: out (send only), in (receive only), or both.
        #[arg(long, default_value = "out")]
        mode: String,
        /// DKIM selector (the name before ._domainkey).
        #[arg(long, default_value = "mb2026")]
        selector: String,
        /// Register an existing key at this path instead of minting one.
        #[arg(long)]
        dkim_key: Option<std::path::PathBuf>,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Change a domain's direction (out / in / both).
    SetMode {
        /// The domain (must be in the registry).
        name: String,
        /// The new direction: out, in, or both.
        #[arg(long)]
        mode: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Rotate a domain's DKIM key: mint a new one under a NEW selector.
    Rekey {
        /// The domain (must be in the registry).
        name: String,
        /// A fresh selector, distinct from the current one.
        #[arg(long)]
        selector: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Remove a domain from the registry (its key file stays on disk).
    Remove {
        /// The domain to remove.
        name: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum ServerCommand {
    /// Show the server settings: the door, TLS, submission, spool + quota.
    Show {
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Change server settings. Provide any of the flags; each is applied.
    Set {
        /// The server's own name (EHLO / PTR / TLS cert name).
        #[arg(long)]
        hostname: Option<String>,
        /// Reject incoming mail that fails DMARC when the sender publishes
        /// p=reject (true), or only annotate it (false).
        #[arg(long)]
        dmarc_enforce: Option<bool>,
        /// Per-mailbox quota in MiB (0 = unlimited).
        #[arg(long)]
        mailbox_quota_mb: Option<u64>,
        /// Spool ceiling in MiB (0 = unlimited).
        #[arg(long)]
        spool_max_mb: Option<u64>,
        /// URL to POST every accepted message to.
        #[arg(long)]
        webhook: Option<String>,
        /// Remove the webhook URL.
        #[arg(long)]
        clear_webhook: bool,
        /// Path to the TLS certificate chain (PEM) for STARTTLS.
        #[arg(long)]
        tls_cert: Option<std::path::PathBuf>,
        /// Path to the TLS private key (PEM) matching tls_cert.
        #[arg(long)]
        tls_key: Option<std::path::PathBuf>,
        /// Remove the configured cert/key (fall back to self-signed).
        #[arg(long)]
        clear_tls: bool,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum ForwardCommand {
    /// Add a rule: mail for <alias> is relayed on to --to.
    Add {
        /// The address we host that should be forwarded.
        alias: String,
        /// Where matching mail is relayed.
        #[arg(long)]
        to: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Remove a forwarding rule by its matched alias.
    Remove {
        /// The alias whose rule to remove.
        alias: String,
        /// Path to mailbourne.toml (same search order as `send`).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// List the forwarding rules, one line each.
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

/// Reads `--attach` values into attachments.
///
/// `path` keeps the file's own name. `Name=path` renames it for the
/// recipient, which is what stops a certificate arriving as
/// `9f2c-4d1a-….pdf`. The `=` is split on the first occurrence, so a path
/// containing one still works.
fn read_attachments(specs: &[String]) -> Result<Vec<mailbourne::shared::mime::Attachment>, String> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let (name, path) = match spec.split_once('=') {
            Some((name, path)) if !name.trim().is_empty() && !path.trim().is_empty() => {
                (Some(name.trim().to_string()), path.trim())
            }
            _ => (None, spec.trim()),
        };
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let filename = name.unwrap_or_else(|| {
            std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "attachment".to_string())
        });
        out.push(mailbourne::shared::mime::Attachment::new(filename, bytes));
    }
    Ok(out)
}

async fn run_command(command: Command) -> i32 {
    match command {
        Command::Send {
            to,
            from,
            subject,
            body,
            html,
            attach,
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

            let attachments = match read_attachments(&attach) {
                Ok(list) => list,
                Err(why) => {
                    eprintln!("✗ {why}");
                    return 1;
                }
            };
            for a in &attachments {
                println!(
                    "  attaching {} …… ✓  {} ({} bytes)",
                    a.filename,
                    a.declared_type(),
                    a.bytes.len()
                );
            }
            println!("  building message (RFC 5322)…… ✓");
            let mut message = mailbourne::shared::compose::rich(
                &from,
                &to,
                &subject,
                &body,
                html.as_deref(),
                &attachments,
                &hostname,
            );

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
            DomainCommand::Add {
                name,
                mode,
                selector,
                dkim_key,
                config,
            } => domain_add(
                &name,
                &mode,
                &selector,
                dkim_key.as_deref(),
                config.as_deref(),
            ),
            DomainCommand::SetMode { name, mode, config } => {
                domain_set_mode(&name, &mode, config.as_deref())
            }
            DomainCommand::Rekey {
                name,
                selector,
                config,
            } => domain_rekey(&name, &selector, config.as_deref()),
            DomainCommand::Remove { name, config } => domain_remove(&name, config.as_deref()),
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
        Command::Server { command } => server_cmd(command),
        Command::Forward { command } => forward_cmd(command),
        Command::Explain { term } => explain_cmd(term.as_deref()),
        Command::Cert { command } => cert_cmd(command).await,
    }
}

/// Parses a mode word (`out` / `in` / `both`) for the CLI.
fn parse_mode(s: &str) -> Option<mailbourne::config::Mode> {
    use mailbourne::config::Mode;
    match s {
        "out" => Some(Mode::Out),
        "in" => Some(Mode::In),
        "both" => Some(Mode::Both),
        _ => None,
    }
}

/// Reads the config text, applies a format-preserving edit, writes it back.
/// Returns a process exit code (0 ok, 2 on a rejected edit or missing file).
fn edit_config<F>(flag: Option<&std::path::Path>, edit: F) -> i32
where
    F: FnOnce(&str) -> Result<String, mailbourne::shared::core::edit::EditError>,
{
    let Some(path) = existing_config_path(flag) else {
        eprintln!("✗ no mailbourne.toml found — nothing is registered yet.");
        eprintln!("  run `mailbourne` to set one up, or point me at it with --config.");
        return 2;
    };
    let toml = match std::fs::read_to_string(&path) {
        Ok(toml) => toml,
        Err(e) => {
            eprintln!("✗ couldn't read {}: {e}", path.display());
            return 1;
        }
    };
    match edit(&toml) {
        Ok(updated) => {
            if let Err(e) = std::fs::write(&path, updated) {
                eprintln!("✗ couldn't write {}: {e}", path.display());
                return 1;
            }
            0
        }
        Err(e) => {
            eprintln!("✗ {e}");
            2
        }
    }
}

/// Loads the ACME account key from `path`, creating and saving it if absent.
fn load_or_create_account(
    path: &std::path::Path,
) -> Result<mailbourne::server::acme::account::AccountKey, i32> {
    use mailbourne::server::acme::account::AccountKey;
    if path.exists() {
        let pem = std::fs::read_to_string(path).map_err(|e| {
            eprintln!("✗ couldn't read {}: {e}", path.display());
            1
        })?;
        AccountKey::from_pem(&pem).map_err(|e| {
            eprintln!("✗ {e}");
            2
        })
    } else {
        let account = AccountKey::generate().map_err(|e| {
            eprintln!("✗ {e}");
            1
        })?;
        let pem = account.to_pem().map_err(|e| {
            eprintln!("✗ {e}");
            1
        })?;
        if let Err(e) = std::fs::write(path, pem) {
            eprintln!("✗ couldn't write {}: {e}", path.display());
            return Err(1);
        }
        println!("  created a new ACME account key at {}", path.display());
        Ok(account)
    }
}

/// `mailbourne cert obtain` — mailbourne's own certbot.
async fn cert_cmd(command: CertCommand) -> i32 {
    use mailbourne::server::acme::{challenge::Http01Responder, order};

    match command {
        CertCommand::Obtain {
            domain,
            email,
            production,
            http_port,
            account_key,
            out_cert,
            out_key,
        } => {
            let account = match load_or_create_account(&account_key) {
                Ok(account) => account,
                Err(code) => return code,
            };

            let addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
            let responder = match Http01Responder::start(addr).await {
                Ok(responder) => responder,
                Err(e) => {
                    eprintln!("✗ couldn't bind port {http_port} for the challenge: {e}");
                    eprintln!(
                        "  port 80 needs privilege — run with sudo, or --http-port for a test."
                    );
                    return 1;
                }
            };

            let directory = if production {
                order::LETSENCRYPT_PRODUCTION
            } else {
                order::LETSENCRYPT_STAGING
            };
            let ca = if production {
                "Let's Encrypt"
            } else {
                "Let's Encrypt STAGING"
            };
            println!("  obtaining a certificate for {domain} via {ca}…");

            let cert = match order::obtain(
                directory,
                &account,
                email.as_deref(),
                &[domain.clone()],
                &responder,
            )
            .await
            {
                Ok(cert) => cert,
                Err(e) => {
                    eprintln!("✗ {e}");
                    return 1;
                }
            };

            let cert_path =
                out_cert.unwrap_or_else(|| std::path::PathBuf::from(format!("{domain}.crt")));
            let key_path =
                out_key.unwrap_or_else(|| std::path::PathBuf::from(format!("{domain}.key")));
            if let Err(e) = std::fs::write(&cert_path, &cert.cert_pem) {
                eprintln!("✗ couldn't write {}: {e}", cert_path.display());
                return 1;
            }
            if let Err(e) = std::fs::write(&key_path, &cert.key_pem) {
                eprintln!("✗ couldn't write {}: {e}", key_path.display());
                return 1;
            }

            println!("✓ certificate → {}", cert_path.display());
            println!("  key         → {}", key_path.display());
            if !production {
                println!(
                    "  ⚠ this was STAGING — not trusted by clients. add --production for a real one."
                );
            }
            println!("  point mailbourne at it in mailbourne.toml:");
            println!("    [server]");
            println!("    tls_cert = \"{}\"", cert_path.display());
            println!("    tls_key  = \"{}\"", key_path.display());
            0
        }
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

/// Resolves an account password: the `--password` flag if given (unattended,
/// for scripts and LLMs), otherwise a hidden, confirmed interactive prompt.
fn resolve_password(provided: Option<String>, address: &str) -> Result<String, i32> {
    match provided {
        Some(password) => Ok(password),
        None => dialoguer::Password::new()
            .with_prompt(format!("Password for {address}"))
            .with_confirmation("Confirm password", "passwords don't match")
            .interact()
            .map_err(|_| 1),
    }
}

/// `mailbourne account add|list|remove|passwd`.
fn account_cmd(command: AccountCommand) -> i32 {
    use mailbourne::server::accounts::hash_password;
    use mailbourne::shared::core::edit;
    match command {
        AccountCommand::Add {
            address,
            password,
            quota_mb,
            config,
        } => {
            if EmailAddress::parse(&address).is_err() {
                eprintln!("✗ an account address must look like someone@somewhere.tld");
                return 2;
            }
            let password = match resolve_password(password, &address) {
                Ok(password) => password,
                Err(code) => return code,
            };
            let hash = match hash_password(&password) {
                Ok(hash) => hash,
                Err(e) => {
                    eprintln!("✗ {e}");
                    return 1;
                }
            };
            let quota_bytes = quota_mb * 1024 * 1024;
            let code = edit_config(config.as_deref(), |toml| {
                edit::add_account(toml, &address, &hash, quota_bytes)
            });
            if code == 0 {
                println!("✓ account {address} added.");
                println!("  it can receive mail now, and send through this server over AUTH+TLS.");
            }
            code
        }
        AccountCommand::Remove { address, config } => {
            let code = edit_config(config.as_deref(), |toml| {
                edit::remove_account(toml, &address)
            });
            if code == 0 {
                println!("✓ account {address} removed (any stored mail on disk is untouched).");
            }
            code
        }
        AccountCommand::Passwd {
            address,
            password,
            config,
        } => {
            let password = match resolve_password(password, &address) {
                Ok(password) => password,
                Err(code) => return code,
            };
            let hash = match hash_password(&password) {
                Ok(hash) => hash,
                Err(e) => {
                    eprintln!("✗ {e}");
                    return 1;
                }
            };
            let code = edit_config(config.as_deref(), |toml| {
                edit::set_account_password(toml, &address, &hash)
            });
            if code == 0 {
                println!("✓ password changed for {address}.");
            }
            code
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

/// `mailbourne domain add` — register a new domain and mint its DKIM key.
fn domain_add(
    name: &str,
    mode: &str,
    selector: &str,
    dkim_key: Option<&std::path::Path>,
    config_flag: Option<&std::path::Path>,
) -> i32 {
    use mailbourne::shared::core::edit;
    let Some(mode) = parse_mode(mode) else {
        eprintln!("✗ mode must be one of: out, in, both");
        return 2;
    };
    let Some(path) = existing_config_path(config_flag) else {
        eprintln!("✗ no mailbourne.toml found — run `mailbourne` to set one up first.");
        return 2;
    };
    // Refuse a duplicate before minting a key we'd otherwise orphan.
    if let Ok(config) = mailbourne::config::Config::load(&path)
        && config.domain(name).is_some()
    {
        eprintln!("✗ {name} is already registered.");
        return 2;
    }

    // Either register an existing key path, or mint a fresh one and print its
    // record. Both go through the same format-preserving edit.
    let (key_value, record) = match dkim_key {
        Some(existing) => (existing.display().to_string(), None),
        None => match mailbourne::cli::actions::mint_domain_key(&path, name, selector) {
            Ok(minted) => (minted.rel_key, Some(minted.dns_record_value)),
            Err(e) => {
                eprintln!("✗ {e}");
                return 1;
            }
        },
    };

    let code = edit_config(config_flag, |toml| {
        edit::add_domain(toml, name, mode, selector, &key_value)
    });
    if code != 0 {
        return code;
    }
    println!("✓ added {name} ({mode:?}).");
    match record {
        Some(value) => {
            println!("  publish this so {name} can be verified (paste at your DNS provider):");
            println!("    {selector}._domainkey.{name}   TXT   {value}");
        }
        None => {
            println!("  using existing key {key_value} — make sure its record is published:");
            println!("    {selector}._domainkey.{name}   TXT   <the public half of that key>");
        }
    }
    0
}

/// `mailbourne domain set-mode` — change a domain's direction.
fn domain_set_mode(name: &str, mode: &str, config_flag: Option<&std::path::Path>) -> i32 {
    use mailbourne::shared::core::edit;
    let Some(mode) = parse_mode(mode) else {
        eprintln!("✗ mode must be one of: out, in, both");
        return 2;
    };
    let code = edit_config(config_flag, |toml| edit::set_domain_mode(toml, name, mode));
    if code == 0 {
        println!("✓ {name} is now {mode:?}.");
        if matches!(mode, mailbourne::config::Mode::Out) {
            println!("  (its MX is left alone — inbound stays with your current provider.)");
        }
    }
    code
}

/// `mailbourne domain rekey` — rotate a domain's DKIM key under a new selector.
fn domain_rekey(name: &str, selector: &str, config_flag: Option<&std::path::Path>) -> i32 {
    use mailbourne::shared::core::edit;
    let Some(path) = existing_config_path(config_flag) else {
        eprintln!("✗ no mailbourne.toml found — run `mailbourne` to set one up first.");
        return 2;
    };
    let minted = match mailbourne::cli::actions::mint_domain_key(&path, name, selector) {
        Ok(minted) => minted,
        Err(e) => {
            eprintln!("✗ {e}");
            return 1;
        }
    };
    let code = edit_config(config_flag, |toml| {
        edit::set_domain_dkim(toml, name, selector, &minted.rel_key)
    });
    if code != 0 {
        return code;
    }
    println!("✓ rotated {name} to selector {selector}.");
    println!("  publish the NEW record BEFORE the next send, or signing will fail:");
    println!(
        "    {selector}._domainkey.{name}   TXT   {}",
        minted.dns_record_value
    );
    println!("  once it verifies, you can delete the old selector's record.");
    0
}

/// `mailbourne domain remove` — take a domain out of the registry.
fn domain_remove(name: &str, config_flag: Option<&std::path::Path>) -> i32 {
    use mailbourne::shared::core::edit;
    let code = edit_config(config_flag, |toml| edit::remove_domain(toml, name));
    if code == 0 {
        println!("✓ removed {name} (its key file stays in keys/; DNS records go unused).");
    }
    code
}

/// `mailbourne server show|set`.
fn server_cmd(command: ServerCommand) -> i32 {
    use mailbourne::shared::core::edit;
    match command {
        ServerCommand::Show { config } => {
            let cfg = match require_config(config.as_deref()) {
                Ok(cfg) => cfg,
                Err(code) => return code,
            };
            println!();
            for line in mailbourne::cli::console::server_summary(&cfg) {
                println!("{line}");
            }
            0
        }
        ServerCommand::Set {
            hostname,
            dmarc_enforce,
            mailbox_quota_mb,
            spool_max_mb,
            webhook,
            clear_webhook,
            tls_cert,
            tls_key,
            clear_tls,
            config,
        } => {
            // Fold every provided flag into one format-preserving pass over
            // the text, so a run either applies cleanly or changes nothing.
            let mut changes: Vec<String> = Vec::new();
            let code = edit_config(config.as_deref(), |toml| {
                let mut doc = toml.to_string();
                if let Some(h) = &hostname {
                    doc = edit::set_server_string(&doc, "hostname", h)?;
                    changes.push(format!("hostname = {h}"));
                }
                if let Some(v) = dmarc_enforce {
                    doc = edit::set_server_bool(&doc, "dmarc_enforce", v)?;
                    changes.push(format!("dmarc_enforce = {v}"));
                }
                if let Some(mb) = mailbox_quota_mb {
                    doc = edit::set_server_int(
                        &doc,
                        "mailbox_quota_bytes",
                        (mb * 1024 * 1024) as i64,
                    )?;
                    changes.push(format!("mailbox_quota = {mb} MiB"));
                }
                if let Some(mb) = spool_max_mb {
                    doc = edit::set_server_int(&doc, "spool_max_bytes", (mb * 1024 * 1024) as i64)?;
                    changes.push(format!("spool_max = {mb} MiB"));
                }
                if clear_webhook {
                    doc = edit::clear_server_field(&doc, "webhook_url")?;
                    changes.push("webhook cleared".to_string());
                } else if let Some(url) = &webhook {
                    doc = edit::set_server_string(&doc, "webhook_url", url)?;
                    changes.push(format!("webhook = {url}"));
                }
                if clear_tls {
                    doc = edit::clear_server_field(&doc, "tls_cert")?;
                    doc = edit::clear_server_field(&doc, "tls_key")?;
                    changes.push("tls cleared (self-signed)".to_string());
                } else {
                    if let Some(c) = &tls_cert {
                        doc = edit::set_server_string(&doc, "tls_cert", &c.display().to_string())?;
                        changes.push(format!("tls_cert = {}", c.display()));
                    }
                    if let Some(k) = &tls_key {
                        doc = edit::set_server_string(&doc, "tls_key", &k.display().to_string())?;
                        changes.push(format!("tls_key = {}", k.display()));
                    }
                }
                Ok(doc)
            });
            if code == 0 {
                if changes.is_empty() {
                    println!(
                        "nothing to change — pass a flag (see `mailbourne server set --help`)."
                    );
                } else {
                    println!("✓ server updated:");
                    for change in &changes {
                        println!("    {change}");
                    }
                }
            }
            code
        }
    }
}

/// `mailbourne forward add|remove|list`.
fn forward_cmd(command: ForwardCommand) -> i32 {
    use mailbourne::shared::core::edit;
    match command {
        ForwardCommand::Add { alias, to, config } => {
            if EmailAddress::parse(&to).is_err() {
                eprintln!("✗ --to must be a full address like someone@somewhere.tld");
                return 2;
            }
            let code = edit_config(config.as_deref(), |toml| {
                edit::add_forward(toml, &alias, &to)
            });
            if code == 0 {
                println!("✓ mail for {alias} will be forwarded to {to}.");
            }
            code
        }
        ForwardCommand::Remove { alias, config } => {
            let code = edit_config(config.as_deref(), |toml| edit::remove_forward(toml, &alias));
            if code == 0 {
                println!("✓ removed the forward for {alias}.");
            }
            code
        }
        ForwardCommand::List { config } => {
            let cfg = match require_config(config.as_deref()) {
                Ok(cfg) => cfg,
                Err(code) => return code,
            };
            if cfg.forwards.is_empty() {
                println!("no forwards yet — add one: mailbourne forward add <alias> --to <dest>");
            } else {
                for f in &cfg.forwards {
                    println!("  {}  →  {}", f.match_recipient, f.to);
                }
            }
            0
        }
    }
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

    // The door: verify SPF/DKIM/DMARC on incoming mail, stamp the result, and
    // (when enabled) reject a domain's own p=reject failures.
    let doorman: Option<std::sync::Arc<dyn mailbourne::server::door::Doorman>> = Some(
        std::sync::Arc::new(mailbourne::server::door::MailAuthDoor::new(
            config.server.hostname.clone(),
            config.server.dmarc_enforce,
        )),
    );
    if config.server.dmarc_enforce {
        println!("   door → SPF/DKIM/DMARC checked; failing p=reject mail refused");
    } else {
        println!("   door → SPF/DKIM/DMARC checked and annotated (enforcement off)");
    }

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
        doorman,
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
