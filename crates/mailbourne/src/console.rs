//! # console — mailbourne's human face (bare `mailbourne`)
//!
//! Chloe at a keyboard. **Cloudflare-style navigation:** home is your list
//! of domains; drill *into* one to manage it, into `server` for the shared
//! settings, `back` climbs out. First run it wizards you; every run after,
//! it's a dashboard.
//!
//! Inline flowing prompts (not an alt-screen TUI) — copy-paste of records
//! stays trivial, it's robust over SSH and `docker exec`, and it matches
//! the "logs are the mentor" voice. A status header prints fresh atop each
//! home loop for the at-a-glance view.
//!
//! The pure screen logic ([`status_header`], [`home_labels`],
//! [`home_choice`]) is testable without a terminal; the interactive loop is
//! a thin `dialoguer` shell over it.

use mailbourne_core::config::{Config, Mode};

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Out => "send-only",
        Mode::In => "receive-only",
        Mode::Both => "send + receive",
    }
}

/// The status board printed atop each home loop. **Local info only** (mode,
/// key on disk) — cheap, no DNS. Live health is the domain screen's
/// inspect, so the loop stays snappy.
pub(crate) fn status_header(config: &Config) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "☕ {}", config.server.hostname);
    if config.domains.is_empty() {
        let _ = writeln!(out, "\n  no domains yet — add one to get started.");
        return out;
    }
    let _ = writeln!(out, "\n  DOMAINS");
    for d in &config.domains {
        let key = match &d.dkim_key {
            Some(p) if p.exists() => "key ✓",
            Some(_) => "key missing",
            None => "no key",
        };
        let _ = writeln!(out, "    {:<26} {:<14} {}", d.name, mode_label(d.mode), key);
    }
    out
}

/// What a home-menu index means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HomeChoice {
    /// Drill into the domain at this registry index.
    Domain(usize),
    /// Add a new domain.
    Add,
    /// Open the server screen.
    Server,
    /// Leave.
    Quit,
}

/// Home-menu labels: every domain, then add / server / quit.
pub(crate) fn home_labels(config: &Config) -> Vec<String> {
    let mut items: Vec<String> = config
        .domains
        .iter()
        .map(|d| format!("{}   ({})", d.name, mode_label(d.mode)))
        .collect();
    items.push("＋ add a domain".into());
    items.push("⚙  server settings".into());
    items.push("quit".into());
    items
}

/// Maps a selected home index to its meaning.
pub(crate) fn home_choice(config: &Config, selected: usize) -> HomeChoice {
    let n = config.domains.len();
    if selected < n {
        HomeChoice::Domain(selected)
    } else if selected == n {
        HomeChoice::Add
    } else if selected == n + 1 {
        HomeChoice::Server
    } else {
        HomeChoice::Quit
    }
}

// ── interactive loop (needs a TTY; gated behind the cli feature) ──────

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

    loop {
        println!("\n{}", status_header(&config));
        let labels = home_labels(&config);
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
        match home_choice(&config, sel) {
            HomeChoice::Domain(i) => domain_screen(handle, &theme, &config, i),
            HomeChoice::Add => {
                if add_domain(&theme, &path, &config) {
                    if let Ok(fresh) = Config::load(&path) {
                        config = fresh;
                    }
                }
            }
            HomeChoice::Server => server_screen(handle, &theme, &config),
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
    loop {
        println!("\n☕ {}  ·  {}", domain.name, mode_label(domain.mode));
        let labels = ["check what's live (inspect)", "back"];
        let sel = match Select::with_theme(theme)
            .items(&labels)
            .default(0)
            .interact_opt()
        {
            Ok(Some(i)) => i,
            _ => return,
        };
        if sel != 0 {
            return;
        }
        println!(
            "\n  asking DNS how the world sees {} right now…",
            domain.name
        );
        match handle.block_on(crate::inspect::domain(config, &domain.name)) {
            Some((sheet, ip)) => {
                let r = crate::sheet::render(&sheet, &domain.name, &config.server.hostname, ip);
                println!("\n{}", r.text);
                if r.to_do == 0 {
                    println!("  lovely — nothing to paste; all sorted. ☕");
                } else {
                    println!("  {} to sort · inspect again after DNS settles", r.to_do);
                }
            }
            None => println!("  (couldn't find {} in the registry — odd.)", domain.name),
        }
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
    println!("\n  then open {name} from the menu and 'inspect' to watch it land. ☕");
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

    fn registry(n: usize) -> Config {
        let mut toml = String::from("[server]\nhostname = \"mail.hq.example.com\"\n");
        for i in 0..n {
            toml.push_str(&format!(
                "\n[[domain]]\nname = \"d{i}.example.com\"\nmode = \"out\"\n"
            ));
        }
        Config::parse_toml(&toml).unwrap()
    }

    #[test]
    fn status_header_lists_every_domain() {
        let header = status_header(&registry(2));
        assert!(header.contains("mail.hq.example.com"));
        assert!(header.contains("d0.example.com"));
        assert!(header.contains("d1.example.com"));
        assert!(header.contains("no key")); // no dkim_key in the fixtures
    }

    #[test]
    fn an_empty_registry_invites_adding_one() {
        let header = status_header(&registry(0));
        assert!(header.contains("no domains yet"));
    }

    #[test]
    fn home_menu_is_domains_then_add_server_quit() {
        let config = registry(2);
        let labels = home_labels(&config);
        assert_eq!(labels.len(), 5); // 2 domains + add + server + quit
        assert!(labels[0].contains("d0.example.com"));
        assert!(labels[2].contains("add"));
        assert!(labels[3].contains("server"));
        assert_eq!(labels[4], "quit");
    }

    #[test]
    fn home_choice_maps_indices_to_meaning() {
        let config = registry(2);
        assert_eq!(home_choice(&config, 0), HomeChoice::Domain(0));
        assert_eq!(home_choice(&config, 1), HomeChoice::Domain(1));
        assert_eq!(home_choice(&config, 2), HomeChoice::Add);
        assert_eq!(home_choice(&config, 3), HomeChoice::Server);
        assert_eq!(home_choice(&config, 4), HomeChoice::Quit);
    }
}
