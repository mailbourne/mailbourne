//! The `mailbourne` command line — a thin shell over the library.
//!
//! Today it carries the Milestone 0 proof tool: `mailbourne send`, which
//! walks one message through the whole outbound journey and narrates every
//! step. The full engine (`run`, `doctor`, `dns`, `learn`) arrives next.

use clap::{Parser, Subcommand};
use mailbourne::out::conversation::Outcome;
use mailbourne::{EmailAddress, Envelope};

#[derive(Parser)]
#[command(
    name = "mailbourne",
    version,
    about = "A Rust-native mail server and library"
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
        } => {
            let (Ok(from), Ok(to)) = (EmailAddress::parse(&from), EmailAddress::parse(&to)) else {
                eprintln!("✗ addresses must look like someone@somewhere.tld");
                return 2;
            };
            let hostname = hostname.unwrap_or_else(|| format!("mail.{}", from.domain()));

            println!("  building message (RFC 5322)…… ✓");
            let mut message =
                mailbourne::compose::plain_text(&from, &to, &subject, &body, &hostname);

            match (&dkim_selector, &dkim_key) {
                (Some(selector), Some(key_path)) => {
                    let domain = dkim_domain.unwrap_or_else(|| from.domain().to_string());
                    let pem = match std::fs::read_to_string(key_path) {
                        Ok(pem) => pem,
                        Err(e) => {
                            eprintln!("✗ could not read {}: {e}", key_path.display());
                            return 2;
                        }
                    };
                    match mailbourne::out::sign::dkim_sign(&message, &domain, selector, &pem) {
                        Ok(signed) => {
                            println!("  DKIM signing ({selector})……… ✓  d={domain}");
                            message = signed;
                        }
                        Err(e) => {
                            eprintln!("✗ refusing to send unsigned: {e}");
                            return 2;
                        }
                    }
                }
                _ => println!("  DKIM signing………………… — skipped (no --dkim-selector/--dkim-key)"),
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
    }
}
