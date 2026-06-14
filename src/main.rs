use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

use air::backend;
use air::globals::State;

// ── CLI definition (Builder pattern via clap derive) ────────────────────

#[derive(Parser)]
#[command(
    name = "air",
    version,
    about = "Air — async Wi-Fi auditing toolkit (C23 + Rust)",
    long_about = None,
)]
struct Cli {
    /// Verbose output (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Skip root-privilege check (testing only)
    #[arg(long, hide = true)]
    no_root_check: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Launch interactive TUI (default when no subcommand given)
    Tui,

    /// List wireless interfaces
    Ifaces,

    /// Scan for access points
    Scan {
        #[arg(short, long)]
        iface: String,
        #[arg(long)]
        band5: bool,
        #[arg(long, value_delimiter = ',')]
        channels: Vec<u8>,
        /// Duration seconds (0 = until Ctrl-C)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },

    /// Crack a WPA/WPA2 handshake
    Crack {
        #[arg(short = 'f', long)]
        cap: String,
        #[arg(short, long)]
        essid: String,
        #[arg(short, long)]
        bssid: String,
        #[arg(short, long)]
        wordlist: Option<String>,
        #[arg(short, long)]
        charset: Option<String>,
        #[arg(long, default_value = "8")]
        min_len: usize,
        #[arg(long, default_value = "12")]
        max_len: usize,
    },

    /// PMKID attack — no 4-way handshake needed
    Pmkid {
        #[arg(long)]
        bssid: String,
        #[arg(long)]
        sta: String,
        /// Captured PMKID hex (32 hex chars = 16 bytes)
        #[arg(long)]
        pmkid: String,
        #[arg(short, long)]
        essid: String,
        #[arg(short, long)]
        wordlist: String,
    },

    /// Bruteforce WPA/WPA2 — no wordlist needed
    Bruteforce {
        #[arg(short = 'f', long)]
        cap: String,
        #[arg(short, long)]
        essid: String,
        #[arg(short, long)]
        bssid: String,
        #[arg(long, default_value = "abcdefghijklmnopqrstuvwxyz0123456789")]
        charset: String,
        #[arg(long, default_value = "8")]
        min_len: usize,
        #[arg(long, default_value = "10")]
        max_len: usize,
    },

    /// WEP crack — delegates to aircrack-ng
    CrackWep {
        #[arg(short = 'f', long)]
        cap: String,
        #[arg(short, long)]
        bssid: String,
    },

    /// Deauth clients from an AP
    Deauth {
        #[arg(short, long)]
        iface: String,
        #[arg(short, long)]
        bssid: String,
        #[arg(short, long, value_delimiter = ',')]
        clients: Vec<String>,
        #[arg(long, default_value = "aireplay")]
        tool: String,
    },

    /// Print current session statistics (JSON)
    Stats,
}

// ── Entry point ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .with_target(false)
        .compact()
        .init();

    if !cli.no_root_check
        && let Err(e) = backend::check_root() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // Graceful shutdown on Ctrl-C
    tokio::spawn(async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("shutting down…");
        State::shutdown();
        std::process::exit(0);
    });

    let result = match cli.command.unwrap_or(Command::Tui) {
        Command::Tui    => run_tui().await,
        Command::Ifaces => cmd_ifaces().await,
        Command::Scan { iface, band5, channels, duration } =>
            cmd_scan(iface, band5, channels, duration).await,
        Command::Crack { cap, essid, bssid, wordlist, charset, min_len, max_len } =>
            cmd_crack(cap, essid, bssid, wordlist, charset, min_len, max_len).await,
        Command::Pmkid { bssid, sta, pmkid, essid, wordlist } =>
            cmd_pmkid(bssid, sta, pmkid, essid, wordlist).await,
        Command::Bruteforce { cap, essid, bssid, charset, min_len, max_len } =>
            cmd_bruteforce(cap, essid, bssid, charset, min_len, max_len).await,
        Command::CrackWep { cap, bssid } =>
            cmd_crack_wep(cap, bssid).await,
        Command::Deauth { iface, bssid, clients, tool } =>
            cmd_deauth(iface, bssid, clients, tool).await,
        Command::Stats  => cmd_stats().await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ── TUI launcher ────────────────────────────────────────────────────────

async fn run_tui() -> air::AirResult<()> {
    if let Err(e) = backend::app_setup().await {
        return Err(air::AirError::Engine(e.to_string()));
    }
    air::tui::run().await
}

// ── CLI command handlers ─────────────────────────────────────────────────

async fn cmd_ifaces() -> air::AirResult<()> {
    let ifaces = backend::list_interfaces().await
        .map_err(|e| air::AirError::Scan(e.to_string()))?;
    if ifaces.is_empty() {
        println!("no wireless interfaces found");
    } else {
        for i in ifaces { println!("{i}"); }
    }
    Ok(())
}

async fn cmd_scan(iface: String, band5: bool, channels: Vec<u8>, duration: u64)
    -> air::AirResult<()>
{
    use air::backend::{ScanConfig, start_scan};
    let mut cfg = ScanConfig::new(&iface);
    if band5 { cfg = cfg.with_5ghz(); }
    if !channels.is_empty() { cfg = cfg.with_channels(channels); }
    tracing::info!("scanning on {} …", iface);
    start_scan(cfg).await.map_err(|e| air::AirError::Scan(e.to_string()))?;
    if duration > 0 {
        tokio::time::sleep(tokio::time::Duration::from_secs(duration)).await;
        State::stop_scan();
    } else {
        std::future::pending::<()>().await;
    }
    Ok(())
}

async fn cmd_crack(
    cap: String, essid: String, bssid: String,
    wordlist: Option<String>, charset: Option<String>,
    min_len: usize, max_len: usize,
) -> air::AirResult<()> {
    use air::engine::WpaEngine;
    use air::wordlist::{BruteforceConfig, WordlistConfig, WordSource};
    use std::sync::Arc;
    use std::path::PathBuf;

    let engine = Arc::new(WpaEngine::new(&essid)?);

    let handshakes = backend::get_handshakes([cap.as_str()])
        .map_err(|e| air::AirError::Capture(e.to_string()))?;
    let hs = Arc::new(
        handshakes.into_iter()
            .find(|h| h.bssid.eq_ignore_ascii_case(&bssid))
            .ok_or(air::AirError::NotFound)?
    );

    // Build word source — Strategy pattern
    let source = if let Some(wl) = wordlist {
        WordSource::Files(WordlistConfig { paths: vec![PathBuf::from(wl)], ..Default::default() })
    } else if let Some(cs) = charset {
        WordSource::Bruteforce(BruteforceConfig::new(cs, min_len, max_len))
    } else {
        return Err(air::AirError::InvalidParam("provide --wordlist or --charset".into()));
    };

    // Subscribe to progress events before cracking starts
    let mut rx = State::subscribe();
    tokio::spawn(async move {
        while let Ok(ev) = rx.recv().await {
            match ev {
                air::types::AppEvent::CrackProgress(p) if p.state == air::types::CrackState::Running => {
                    eprint!("\r  {} candidates  {}  ETA {}     ",
                        p.tried, p.speed_display(), p.eta_display());
                }
                air::types::AppEvent::CrackFound { password, .. } => {
                    eprintln!();
                    println!("\n  ✓ PASSWORD FOUND: {password}");
                    break;
                }
                air::types::AppEvent::CrackExhausted { tried, .. } => {
                    eprintln!();
                    println!("  ✗ not found after {tried} candidates");
                    break;
                }
                _ => {}
            }
        }
    });

    if let Some(r) = WpaEngine::crack_auto(engine, hs, source).await? {
        println!("  PMK: {}", hex_str(&r.pmk));
        println!("  tried: {}", r.tried);
    }
    Ok(())
}

async fn cmd_pmkid(
    bssid: String, sta: String, pmkid_hex: String,
    essid: String, wordlist: String,
) -> air::AirResult<()> {
    use air::engine::WpaEngine;
    use air::wordlist::{WordlistConfig, WordSource};
    use std::sync::Arc;
    use std::path::PathBuf;

    let mut pmkid_bytes = [0u8; 16];
    let raw = parse_hex(&pmkid_hex).map_err(air::AirError::InvalidParam)?;
    if raw.len() != 16 {
        return Err(air::AirError::InvalidParam("PMKID must be 16 bytes".into()));
    }
    pmkid_bytes.copy_from_slice(&raw);

    let ap_mac  = parse_mac(&bssid)?;
    let sta_mac = parse_mac(&sta)?;
    let engine  = Arc::new(WpaEngine::new(&essid)?);

    let source = WordSource::Files(WordlistConfig {
        paths: vec![PathBuf::from(wordlist)],
        ..Default::default()
    });
    let total = source.count_hint().await;

    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<String>>(64);
    tokio::spawn(async move { let _ = source.stream_into(tx).await; });

    match WpaEngine::crack_pmkid_channel(
        engine, pmkid_bytes, ap_mac, sta_mac,
        essid, bssid, total, rx,
    ).await? {
        Some(r) => {
            println!("\n  PMKID CRACKED: {}", r.password);
            println!("  PMK: {}", hex_str(&r.pmk));
            println!("  tried {} candidates", r.tried);
        }
        None => println!("password not found"),
    }
    Ok(())
}

async fn cmd_bruteforce(
    cap: String, essid: String, bssid: String,
    charset: String, min_len: usize, max_len: usize,
) -> air::AirResult<()> {
    use air::engine::WpaEngine;
    use air::wordlist::{BruteforceConfig, WordSource};
    use std::sync::Arc;

    let engine = Arc::new(WpaEngine::new(&essid)?);
    let handshakes = backend::get_handshakes([cap.as_str()])
        .map_err(|e| air::AirError::Capture(e.to_string()))?;
    let hs = Arc::new(
        handshakes.into_iter()
            .find(|h| h.bssid.eq_ignore_ascii_case(&bssid))
            .ok_or(air::AirError::NotFound)?
    );

    let cfg = BruteforceConfig::new(charset, min_len, max_len);
    let total = cfg.candidate_count();
    println!("  bruteforce: {} candidates  len {}-{}", total, cfg.min_len, cfg.max_len);

    let source = WordSource::Bruteforce(cfg);

    match WpaEngine::crack_auto(engine, hs, source).await? {
        Some(r) => {
            println!("\n  ✓ PASSWORD FOUND: {}", r.password);
            println!("  PMK: {}", hex_str(&r.pmk));
            println!("  tried: {}", r.tried);
        }
        None => println!("  ✗ not found"),
    }
    Ok(())
}

async fn cmd_crack_wep(cap: String, bssid: String) -> air::AirResult<()> {
    use air::engine::WpaEngine;
    println!("  WEP crack: {} bssid {}", cap, bssid);
    match WpaEngine::crack_wep(&cap, &bssid).await? {
        Some(key) => println!("  KEY FOUND: {key}"),
        None      => println!("  not found — need more IVs"),
    }
    Ok(())
}

async fn cmd_stats() -> air::AirResult<()> {
    let s = air::globals::AppStats::collect();
    println!("{{");
    println!("  \"ap_count\":       {},", s.ap_count);
    println!("  \"client_count\":   {},", s.client_count);
    println!("  \"unlinked\":       {},", s.unlinked_count);
    println!("  \"active_attacks\": {},", s.active_attacks);
    println!("  \"is_scanning\":    {},", s.is_scanning);
    println!("  \"has_update\":     {},", s.has_update);
    println!("  \"iface\":          {:?},", s.iface);
    println!("  \"session_tried\":  {}", State::session_total_tried());
    println!("}}");
    Ok(())
}

async fn cmd_deauth(iface: String, bssid: String, clients: Vec<String>, tool_str: String)
    -> air::AirResult<()>
{
    use air::types::{Ap, AttackTool};
    use air::backend::launch_deauth;

    let tool = if tool_str.to_lowercase() == "mdk4" { AttackTool::Mdk4 } else { AttackTool::Aireplay };
    State::set_iface(Some(iface));
    let ap = Ap { bssid: bssid.clone(), ..Default::default() };
    let targets = if clients.is_empty() { None } else { Some(clients) };
    launch_deauth(ap, targets, tool).await.map_err(|e| air::AirError::Deauth(e.to_string()))?;
    tracing::info!("deauth running — Ctrl-C to stop");
    std::future::pending::<()>().await;
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.replace([':', ' '], "");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn parse_mac(s: &str) -> air::AirResult<[u8; 6]> {
    let bytes = parse_hex(s).map_err(air::AirError::InvalidParam)?;
    if bytes.len() != 6 {
        return Err(air::AirError::InvalidParam(format!("bad MAC: {s}")));
    }
    let mut m = [0u8; 6];
    m.copy_from_slice(&bytes);
    Ok(m)
}

