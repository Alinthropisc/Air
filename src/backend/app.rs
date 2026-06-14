use tokio::signal;
use tracing::{info, warn};

use crate::globals::State;
use super::*;



#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Root privileges required - run with sudo")]
    NotRoot,

    #[error("Missing required dependency: '{0}' not found in PATH")]
    MissingDep(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Setup failed: {0}")]
    Setup(String),
}


// Tools we need from the system
const REQUIRED_DEPS: &[&str] = &[
    "sh",
    "ip",
    "iw",
    "awk",
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",  // still used as fallback
    "aircrack-ng",
    "mergecap",
    "macchanger",
];

// Optional tools - warn but don't fail
const OPTIONAL_DEPS: &[&str] = &[
    "mdk4",
    "hashcat",
    "hcxdumptool",  // PMKID capture
    "hcxtools",
];


// Initialize Air - call once at startup
// Returns Ok if all required deps found and running as root
pub async fn app_setup() -> Result<(), AppError> {
    // cleanup any leftover state from previous run
    app_cleanup().await;

    // must be root for raw sockets + monitor mode
    if !is_root() {
        return Err(AppError::NotRoot);
    }

    // load user settings from disk
    load_settings().await;

    // check required tools
    check_deps(REQUIRED_DEPS)?;

    // warn about optional tools
    for dep in OPTIONAL_DEPS {
        if !has_dep(dep) {
            warn!("optional tool '{}' not found - some features disabled", dep);
        }
    }

    info!("Air initialized successfully");
    Ok(())
}

// Graceful shutdown handler
// Spawns background task listening for Ctrl-C / SIGTERM
pub fn spawn_shutdown_handler() {
    tokio::spawn(async move {
        // wait for Ctrl-C or SIGTERM
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("failed to install Ctrl-C handler");
        };

        #[cfg(unix)]
        let sigterm = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let sigterm = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c  => info!("received Ctrl-C"),
            _ = sigterm => info!("received SIGTERM"),
        }

        info!("shutting down...");
        app_cleanup().await;
        std::process::exit(0);
    });
}

// Stop all processes and clean up temp files
pub async fn app_cleanup() {
    info!("running cleanup...");

    // stop active scan
    scan::stop_scan().await.ok();

    // kill all deauth attacks
    deauth::stop_all_attacks().await;

    // disable monitor mode if we enabled it
    if let Some(iface) = State::get_iface() {
        if let Err(e) = interface::disable_monitor(&iface).await {
            warn!("could not disable monitor mode: {}", e);
        }
    }

    // restore network services we killed
    interface::restore_network_services().await.ok();

    // delete temp scan files
    cleanup_temp_files().await;

    info!("cleanup complete");
}

async fn cleanup_temp_files() {
    use crate::globals::*;
    use tokio::fs;

    let paths = [
        format!("{}-01.cap", LIVE_SCAN_PATH),
        format!("{}-01.csv", LIVE_SCAN_PATH),
        format!("{}-01.cap", OLD_SCAN_PATH),
    ];

    for path in &paths {
        if let Err(e) = fs::remove_file(path).await {
            // not found is fine - other errors worth logging
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("could not remove '{}': {}", path, e);
            }
        }
    }
}


pub fn has_dep(name: &str) -> bool {
    which::which(name).is_ok()
}

pub fn check_deps(deps: &[&str]) -> Result<(), AppError> {
    for dep in deps {
        if !has_dep(dep) {
            return Err(AppError::MissingDep(dep.to_string()));
        }
    }
    Ok(())
}


pub fn is_root() -> bool {
    #[cfg(unix)]
    return unsafe { libc::getuid() == 0 };
    #[cfg(not(unix))]
    return false;
}


/// Thin wrapper called from main.rs — returns Err if not running as root.
pub fn check_root() -> crate::AirResult<()> {
    if !is_root() {
        return Err(crate::AirError::Engine(
            "root privileges required — run with sudo".into(),
        ));
    }
    Ok(())
}

/// Blocking version of the update check (runs inside spawn_blocking).
pub fn check_for_update_sync(current: &str) -> Option<String> {
    let url = "https://api.github.com/repos/your-org/air/releases/latest";
    let body: serde_json::Value = ureq::get(url)
        .header("User-Agent", &format!("Air/{}", current))
        .config()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .call()
        .ok()?
        .body_mut()
        .read_json()
        .ok()?;
    let latest = body["tag_name"].as_str()?;
    if latest != current {
        info!("new version available: {}", latest);
        Some(latest.to_string())
    } else {
        info!("already up to date");
        None
    }
}

/// Async update check — offloads HTTP onto a thread-pool thread.
pub async fn check_for_update(current: &str) -> Option<String> {
    let cur = current.to_string();
    tokio::task::spawn_blocking(move || check_for_update_sync(&cur))
        .await
        .ok()
        .flatten()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_dep_sh() {
        // sh is always available on Linux
        assert!(has_dep("sh"));
    }

    #[test]
    fn test_has_dep_missing() {
        assert!(!has_dep("this_tool_does_not_exist_12345"));
    }

    #[test]
    fn test_check_deps_ok() {
        assert!(check_deps(&["sh"]).is_ok());
    }

    #[test]
    fn test_check_deps_missing() {
        let result = check_deps(&["this_tool_does_not_exist_12345"]);
        assert!(matches!(result, Err(AppError::MissingDep(_))));
    }

    #[tokio::test]
    async fn test_cleanup_no_panic() {
        // cleanup should never panic even with no state
        app_cleanup().await;
    }
}