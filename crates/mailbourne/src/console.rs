//! # console — mailbourne's human face (bare `mailbourne`)
//!
//! Chloe at a keyboard. **Cloudflare-style navigation:** home is your list
//! of domains; drill *into* one to manage it, into `server` for the shared
//! settings, `back` climbs out. First run it wizards you; every run after,
//! it's a dashboard.
//!
//! Inline flowing prompts (not an alt-screen TUI) — copy-paste of records
//! stays trivial, it's robust over SSH and `docker exec`, and it matches
//! the "logs are the mentor" voice.
//!
//! The tone is encouragement, never blame: a domain has "N to improve",
//! never "N errors". The pure screen logic ([`encouragement`],
//! [`home_labels`], [`home_choice`]) is testable without a terminal; the
//! interactive loop is a thin `dialoguer` shell over it.

use mailbourne_core::config::{Config, Mode};

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Out => "send-only",
        Mode::In => "receive-only",
        Mode::Both => "send + receive",
    }
}

/// A domain's headline status for the home list: how many records still
/// want attention. `None` means we couldn't check (no network / not probed).
#[derive(Debug, Clone)]
pub(crate) struct DomainStatus {
    /// The domain name.
    pub name: String,
    /// Its direction.
    pub mode: Mode,
    /// Count of records to improve, or `None` if unchecked.
    pub to_do: Option<usize>,
}

/// The encouraging one-liner for a domain's status. Never "error" — Chloe
/// frames everything as growth: all sorted, or `N to improve`.
pub(crate) fn encouragement(to_do: Option<usize>) -> String {
    match to_do {
        Some(0) => "all sorted ☕".to_string(),
        Some(n) => format!("{n} to improve"),
        None => "let's have a look".to_string(),
    }
}

/// Home-menu labels: each domain as a selectable status line, then the
/// add / server / refresh / quit actions.
pub(crate) fn home_labels(statuses: &[DomainStatus]) -> Vec<String> {
    let mut items: Vec<String> = statuses
        .iter()
        .map(|s| {
            let who = format!("*@{}", s.name);
            format!(
                "{:<26} {:<16} {}",
                who,
                mode_label(s.mode),
                encouragement(s.to_do)
            )
        })
        .collect();
    items.push("＋ add a domain".into());
    items.push("⚙  server settings".into());
    items.push("↻ refresh".into());
    items.push("quit".into());
    items
}

/// What a home-menu index means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HomeChoice {
    /// Drill into the domain at this index.
    Domain(usize),
    /// Add a new domain.
    Add,
    /// Open the server screen.
    Server,
    /// Re-probe every domain's status.
    Refresh,
    /// Leave.
    Quit,
}

/// Maps a selected home index to its meaning, given how many domains lead
/// the list.
pub(crate) fn home_choice(domain_count: usize, selected: usize) -> HomeChoice {
    let n = domain_count;
    if selected < n {
        HomeChoice::Domain(selected)
    } else if selected == n {
        HomeChoice::Add
    } else if selected == n + 1 {
        HomeChoice::Server
    } else if selected == n + 2 {
        HomeChoice::Refresh
    } else {
        HomeChoice::Quit
    }
}

// ── interactive loop (needs a TTY; gated behind the cli feature) ──────

/// Gathers each domain's live status (records still to improve). Sequential
/// — fine for a handful of domains; concurrency is a later optimisation.
#[cfg(feature = "cli")]
async fn gather_home_status(config: &Config) -> Vec<DomainStatus> {
    use crate::sheet::RowStatus;
    let mut out = Vec::new();
    for d in &config.domains {
        let to_do = match crate::inspect::domain(config, &d.name).await {
            Some((sheet, _)) => Some(
                sheet
                    .rows
                    .iter()
                    .filter(|r| !matches!(r.status, RowStatus::AlreadyCorrect))
                    .count(),
            ),
            None => None,
        };
        out.push(DomainStatus {
            name: d.name.clone(),
            mode: d.mode,
            to_do,
        });
    }
    out
}

/// Runs the console. Sync (dialoguer is blocking); async probes go through
/// `handle`, which is safe because this is called from the main thread,
/// never from inside the runtime.
#[cfg(feature = "cli")]
pub fn run(handle: &tokio::runtime::Handle, config_path: Option<std::path::PathBuf>) -> i32 {
    use dialoguer::Select;
    use dialoguer::theme::ColorfulTheme;

    let theme = ColorfulTheme::default();

    let (path, mut config) = match locate_config(config_path) {
        Some(found) => found,
        None => match first_run(&theme) {
            Some(found) => found,
            None => return 0,
        },
    };

    println!("\n  checking your domains…");
    let mut statuses = handle.block_on(gather_home_status(&config));

    loop {
        println!("\n☕ {}", config.server.hostname);
        if statuses.is_empty() {
            println!("  no domains yet — add one to get started.");
        }
        let labels = home_labels(&statuses);
        let sel = match Select::with_theme(&theme)
            .items(&labels)
            .default(0)
            .interact_opt()
        {
            Ok(Some(i)) => i,
            _ => {
                println!("  ☕ see you.");
                return 0;
            }
        };
        match home_choice(statuses.len(), sel) {
            HomeChoice::Domain(i) => {
                domain_screen(handle, &theme, &config, i);
                statuses = handle.block_on(gather_home_status(&config));
            }
            HomeChoice::Add => {
                if add_domain(&theme, &path, &config) {
                    if let Ok(fresh) = Config::load(&path) {
                        config = fresh;
                    }
                    statuses = handle.block_on(gather_home_status(&config));
                }
            }
            HomeChoice::Server => server_screen(handle, &theme, &config),
            HomeChoice::Refresh => {
                println!("  checking…");
                statuses = handle.block_on(gather_home_status(&config));
            }
            HomeChoice::Quit => {
                println!("  ☕ see you.");
                return 0;
            }
        }
    }
}

#[cfg(feature = "cli")]
fn domain_screen(
    handle: &tokio::runtime::Handle,
    theme: &dialoguer::theme::ColorfulTheme,
    config: &Config,
    idx: usize,
) {
    use dialoguer::Select;
    let domain = &config.domains[idx];

    // Land on the verdict, not a blank menu: inspect live on entry.
    println!("\n  checking *@{} live…", domain.name);
    let mut cached = handle.block_on(crate::inspect::domain(config, &domain.name));

    loop {
        println!("\n☕ *@{}  ·  {}", domain.name, mode_label(domain.mode));
        println!("   mail via {}", config.server.hostname);
        match &cached {
            Some((sheet, _)) => {
                println!("\n   HEALTH   (paste anything marked ⚠ at your DNS provider)");
                print!("{}", crate::sheet::render_health(sheet));
                let to_do = crate::sheet::count_to_do(sheet);
                println!("\n   {}", encouragement(Some(to_do)));
            }
            None => println!("\n   (couldn't reach DNS — try 're-check')"),
        }

        let labels = [
            "re-check live",
            "send a test email",
            "rotate the DKIM key",
            "change mode",
            "remove this domain",
            "back",
        ];
        let sel = match Select::with_theme(theme)
            .items(&labels)
            .default(0)
            .interact_opt()
        {
            Ok(Some(i)) => i,
            _ => return,
        };
        match sel {
            0 => {
                println!(
                    "\n  asking DNS how the world sees {} right now…",
                    domain.name
                );
                cached = handle.block_on(crate::inspect::domain(config, &domain.name));
            }
            1 => send_test(handle, theme, config, &domain.name),
            2 => {
                println!("\n  rotating a DKIM key — coming soon.");
                println!("  it'll mint a fresh key under a new selector and keep the old");
                println!("  one valid until you've published the new record. no downtime.");
            }
            3 => {
                println!("\n  changing mode — coming soon (needs safe config editing).");
                println!("  for now, edit the `mode` line in your mailbourne.toml by hand.");
            }
            4 => {
                println!("\n  removing a domain — coming soon (needs safe config editing).");
                println!("  for now, delete its [[domain]] block from mailbourne.toml.");
            }
            _ => return,
        }
    }
}

/// Send one signed proof email from `domain_name`, narrating the result.
#[cfg(feature = "cli")]
fn send_test(
    handle: &tokio::runtime::Handle,
    theme: &dialoguer::theme::ColorfulTheme,
    config: &Config,
    domain_name: &str,
) {
    use crate::out::conversation::Outcome;
    use dialoguer::Input;
    use mailbourne_core::{EmailAddress, Envelope};

    let to: String = match Input::<String>::with_theme(theme)
        .with_prompt("send a test to (an inbox you can open)")
        .interact_text()
    {
        Ok(t) => t.trim().to_string(),
        Err(_) => return,
    };
    let from = format!("proof@{domain_name}");
    let (Ok(to_addr), Ok(from_addr)) = (EmailAddress::parse(&to), EmailAddress::parse(&from))
    else {
        println!("  that address doesn't look right — try again.");
        return;
    };

    let id = crate::identity::resolve(
        Some(config),
        &from_addr,
        &crate::identity::Overrides::default(),
    );
    for note in &id.notes {
        println!("  · {note}");
    }
    let mut message = crate::compose::plain_text(
        &from_addr,
        &to_addr,
        "mailbourne test ☕",
        "A quick test, sent from mailbourne's console.",
        &id.hostname,
    );
    if let Some(dkim) = &id.dkim {
        match std::fs::read_to_string(&dkim.key_path) {
            Ok(pem) => {
                match crate::out::sign::dkim_sign(&message, &dkim.domain, &dkim.selector, &pem) {
                    Ok(signed) => {
                        println!("  DKIM signed ({}) ✓", dkim.selector);
                        message = signed;
                    }
                    Err(e) => {
                        println!("  ✗ won't send unsigned: {e}");
                        return;
                    }
                }
            }
            Err(e) => {
                println!("  ✗ couldn't read the key: {e}");
                return;
            }
        }
    }

    let envelope = Envelope {
        mail_from: from_addr,
        rcpt_to: vec![to_addr.clone()],
    };
    println!("  routing to {} and sending…", to_addr.domain());
    match handle.block_on(crate::out::send(&id.hostname, &envelope, &message)) {
        Ok(Outcome::Delivered { reply }) => {
            println!("  ★ accepted — {} {}", reply.code, reply.lines.join(" "));
            println!("  open that inbox and check 'show original' for SPF/DKIM/DMARC.");
        }
        Ok(Outcome::Deferred { reply, .. }) => {
            println!("  ⏳ deferred — {} {}", reply.code, reply.lines.join(" "));
            println!("  \"not now\" — worth another go shortly (greylisting?).");
        }
        Ok(Outcome::Rejected { at, reply }) => {
            println!(
                "  ✗ rejected at {at:?} — {} {}",
                reply.code,
                reply.lines.join(" ")
            );
        }
        Err(e) => println!("  ✗ {e}"),
    }
}

#[cfg(feature = "cli")]
fn server_screen(
    handle: &tokio::runtime::Handle,
    theme: &dialoguer::theme::ColorfulTheme,
    config: &Config,
) {
    use dialoguer::Select;
    let ip = handle
        .block_on(crate::probe::dns::a(&config.server.hostname))
        .unwrap_or_default();
    println!("\n☕ {}  ·  the server (the van)", config.server.hostname);
    match ip.first() {
        Some(ip) => println!("    IP            {ip}"),
        None => println!("    IP            does not resolve yet"),
    }
    println!("    port 25       — checked with the receiving daemon (coming)");
    println!("    reverse DNS   — set at your VPS provider (coming: guided)");
    println!("    TLS cert      — auto via ACME (coming with serving)");
    let _ = Select::with_theme(theme)
        .items(&["back"])
        .default(0)
        .interact_opt();
}

#[cfg(feature = "cli")]
fn add_domain(
    theme: &dialoguer::theme::ColorfulTheme,
    config_path: &std::path::Path,
    config: &Config,
) -> bool {
    use dialoguer::{Input, Select};
    use std::io::Write;

    let name: String = match Input::<String>::with_theme(theme)
        .with_prompt("domain to add (e.g. news.example.com)")
        .interact_text()
    {
        Ok(n) => n.trim().to_string(),
        Err(_) => return false,
    };
    if name.is_empty() {
        return false;
    }
    if config.domain(&name).is_some() {
        println!("  {name} is already registered.");
        return false;
    }

    let modes = [
        "send-only (out)",
        "send + receive (both)",
        "receive-only (in)",
    ];
    let m = Select::with_theme(theme)
        .with_prompt("what will this domain do?")
        .items(&modes)
        .default(0)
        .interact()
        .unwrap_or(0);
    let mode_str = ["out", "both", "in"][m];
    let selector = "mb2026";

    let pair = match crate::out::sign::generate_dkim_keypair() {
        Ok(p) => p,
        Err(e) => {
            println!("  ✗ couldn't mint a key: {e}");
            return false;
        }
    };

    // Keys live next to the config, so it travels with them.
    let keydir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("keys");
    let _ = std::fs::create_dir_all(&keydir);
    let keyfile = keydir.join(format!("{name}.pem"));
    if std::fs::write(&keyfile, &pair.private_key_pem).is_err() {
        println!("  ✗ couldn't write the key file.");
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600));
    }

    // Append a fresh [[domain]] table — the header resets TOML context, so
    // this is safe regardless of what the file ended with, and it leaves
    // every existing line (and comment) untouched.
    let block = format!(
        "\n[[domain]]\nname = \"{name}\"\nmode = \"{mode_str}\"\ndkim_selector = \"{selector}\"\ndkim_key = \"keys/{name}.pem\"\n"
    );
    match std::fs::OpenOptions::new().append(true).open(config_path) {
        Ok(mut f) => {
            if f.write_all(block.as_bytes()).is_err() {
                println!("  ✗ couldn't update the config.");
                return false;
            }
        }
        Err(_) => {
            println!("  ✗ couldn't open the config to update it.");
            return false;
        }
    }

    // Ledger Law: end by showing what to publish.
    println!("\n  ✓ added {name} — minted its DKIM key, registered it in the config.");
    println!("\n  publish this to get {name} signing (paste at your DNS provider):");
    println!(
        "    {selector}._domainkey.{name}   TXT   {}",
        pair.dns_record_value
    );
    println!("\n  then open *@{name} from the menu and 'inspect' to watch it land. ☕");
    true
}

/// The default config search: `MAILBOURNE_CONFIG`, `./mailbourne.toml`,
/// `/var/mailbourne/mailbourne.toml`. First that exists and parses wins.
#[cfg(feature = "cli")]
fn locate_config(explicit: Option<std::path::PathBuf>) -> Option<(std::path::PathBuf, Config)> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(p) = explicit {
        candidates.push(p);
    }
    if let Some(env) = std::env::var_os("MAILBOURNE_CONFIG") {
        candidates.push(env.into());
    }
    candidates.push("mailbourne.toml".into());
    candidates.push("/var/mailbourne/mailbourne.toml".into());

    for path in candidates {
        if path.exists() {
            if let Ok(config) = Config::load(&path) {
                println!("  (config: {})", path.display());
                return Some((path, config));
            }
        }
    }
    None
}

/// First-run: no config anywhere. Offer to create one.
#[cfg(feature = "cli")]
fn first_run(theme: &dialoguer::theme::ColorfulTheme) -> Option<(std::path::PathBuf, Config)> {
    use dialoguer::{Confirm, Input};

    println!("\n  ☕ morning — I'm mailbourne. nothing set up here yet, so let's fix that.");
    let go = Confirm::with_theme(theme)
        .with_prompt("set up a mail server now?")
        .default(true)
        .interact()
        .unwrap_or(false);
    if !go {
        println!("  no worries — run me again whenever you're ready.");
        return None;
    }

    let hostname: String = Input::<String>::with_theme(theme)
        .with_prompt("your server's hostname (the van's name, e.g. mail.example.com)")
        .interact_text()
        .ok()?;
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return None;
    }

    let path = std::path::PathBuf::from("mailbourne.toml");
    let toml = format!(
        "# mailbourne — the server, and the domains it carries.\n[server]\nhostname = \"{hostname}\"\n"
    );
    if std::fs::write(&path, toml).is_err() {
        println!("  ✗ couldn't write mailbourne.toml here.");
        return None;
    }
    println!("  ✓ wrote mailbourne.toml — add your first domain from the menu.");
    let config = Config::load(&path).ok()?;
    Some((path, config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statuses() -> Vec<DomainStatus> {
        vec![
            DomainStatus {
                name: "musiklib.org".into(),
                mode: Mode::Both,
                to_do: Some(0),
            },
            DomainStatus {
                name: "id.zebflow.com".into(),
                mode: Mode::Out,
                to_do: Some(2),
            },
        ]
    }

    #[test]
    fn encouragement_never_says_error() {
        assert_eq!(encouragement(Some(0)), "all sorted ☕");
        assert_eq!(encouragement(Some(2)), "2 to improve");
        assert_eq!(encouragement(None), "let's have a look");
        assert!(!encouragement(Some(3)).to_lowercase().contains("error"));
    }

    #[test]
    fn home_lines_are_selectable_status_rows() {
        let labels = home_labels(&statuses());
        assert!(labels[0].contains("*@musiklib.org"));
        assert!(labels[0].contains("all sorted"));
        assert!(labels[1].contains("*@id.zebflow.com"));
        assert!(labels[1].contains("2 to improve"));
        // domains, then add / server / refresh / quit
        assert_eq!(labels.len(), 6);
        assert!(labels[2].contains("add"));
        assert!(labels[3].contains("server"));
        assert!(labels[4].contains("refresh"));
        assert_eq!(labels[5], "quit");
    }

    #[test]
    fn home_choice_maps_indices_including_refresh() {
        assert_eq!(home_choice(2, 0), HomeChoice::Domain(0));
        assert_eq!(home_choice(2, 1), HomeChoice::Domain(1));
        assert_eq!(home_choice(2, 2), HomeChoice::Add);
        assert_eq!(home_choice(2, 3), HomeChoice::Server);
        assert_eq!(home_choice(2, 4), HomeChoice::Refresh);
        assert_eq!(home_choice(2, 5), HomeChoice::Quit);
    }

    #[test]
    fn an_empty_registry_still_offers_the_actions() {
        let labels = home_labels(&[]);
        assert_eq!(
            labels,
            vec!["＋ add a domain", "⚙  server settings", "↻ refresh", "quit"]
        );
        assert_eq!(home_choice(0, 0), HomeChoice::Add);
    }
}
