use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

use crate::globals::State;


#[derive(thiserror::Error, Debug)]
pub enum IfaceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Could not list interfaces")]
    ListFailed,

    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Interface '{0}' not found")]
    NotFound(String),

    #[error("Interface must be in monitor mode first")]
    NotMonitor,

    #[error("Invalid MAC address in settings")]
    BadMac,

    #[error("Monitor mode failed on '{0}': {1}")]
    MonitorFailed(String, String),

    #[error("Managed mode failed on '{0}': {1}")]
    ManagedFailed(String, String),

    #[error("systemctl required but not found")]
    NoSystemd,

    #[error("PHY detection failed")]
    PhyFailed,
}


// List all available wireless interfaces
pub async fn list_interfaces() -> Result<Vec<String>, IfaceError> {
    let out = Command::new("sh").args(["-c", "iw dev | awk '$1==\"Interface\"{print $2}'"]).output().await.map_err(IfaceError::Io)?;

    if !out.status.success() {
        return Err(IfaceError::ListFailed);
    }
    let text = String::from_utf8(out.stdout)?;
    Ok(text.lines().map(String::from).collect())
}

// Check if interface is in monitor mode
pub async fn is_monitor(iface: &str) -> Result<bool, IfaceError> {
    let out = Command::new("iw").args(["dev", iface, "info"]).output().await.map_err(IfaceError::Io)?;

    if !out.status.success() {
        return Err(IfaceError::NotFound(iface.to_string()));
    }
    let text = String::from_utf8(out.stdout)?;
    Ok(text.contains("type monitor"))
}

// Check if interface supports 5GHz
pub async fn supports_5ghz(iface: &str) -> Result<bool, IfaceError> {
    let phy_path = format!("/sys/class/net/{}/phy80211", iface);
    let link = tokio::fs::read_link(&phy_path).await.map_err(IfaceError::Io)?;
    let phy = link.file_name().and_then(|n| n.to_str()).ok_or(IfaceError::PhyFailed)?.to_string();
    let out = Command::new("iw").args(["phy", &phy, "info"]).output().await.map_err(IfaceError::Io)?;
    let text = String::from_utf8(out.stdout)?;
    Ok(text.contains("5200 MHz") || text.contains("5200.0 MHz"))
}


// Enable monitor mode - returns actual monitor interface name
pub async fn enable_monitor(iface: &str) -> Result<String, IfaceError> {
    // check if already in monitor mode
    if is_monitor(iface).await? {
        State::set_iface_was_monitor(true);
        info!("{}: already in monitor mode", iface);
        return Ok(iface.to_string());
    }
    // kill interfering services first
    kill_network_services().await?;
    let old_ifaces = list_interfaces().await?;
    // pipe yes to airmon-ng to auto-confirm killing processes
    let yes = Command::new("yes").stdout(Stdio::piped()).spawn().map_err(IfaceError::Io)?;
    let out = Command::new("airmon-ng").args(["start", iface]).stdin(yes.stdout.unwrap()).output().await.map_err(IfaceError::Io)?;

    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stdout).to_string();
        return Err(IfaceError::MonitorFailed(iface.to_string(), msg));
    }
    info!("{}: monitor mode enabled", iface);

    // try common naming conventions
    if is_monitor(iface).await.unwrap_or(false) {
        return Ok(iface.to_string());
    }
    let mon_name = format!("{}mon", iface);

    if is_monitor(&mon_name).await.unwrap_or(false) {
        return Ok(mon_name);
    }
    // find any new interface that appeared and is in monitor mode
    let new_ifaces = list_interfaces().await?;

    for new_iface in new_ifaces {
        if !old_ifaces.contains(&new_iface)
            && is_monitor(&new_iface).await.unwrap_or(false)
        {
            return Ok(new_iface);
        }
    }
    let msg = String::from_utf8_lossy(&out.stdout).to_string();
    Err(IfaceError::MonitorFailed(iface.to_string(), msg))
}

// Disable monitor mode
pub async fn disable_monitor(iface: &str) -> Result<(), IfaceError> {
    if !is_monitor(iface).await.unwrap_or(false) {
        return Ok(()); // already managed
    }

    // if interface was already in monitor before we touched it - leave it
    if State::get_iface_was_monitor() {
        State::set_iface_was_monitor(false);
        info!("{}: was already monitor - leaving as is", iface);
        return Ok(());
    }
    let out = Command::new("airmon-ng").args(["stop", iface]).output().await.map_err(IfaceError::Io)?;

    if out.status.success() {
        info!("{}: monitor mode disabled", iface);
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stdout).to_string();
        Err(IfaceError::ManagedFailed(iface.to_string(), msg))
    }
}


// Change MAC address based on settings
pub async fn apply_mac_address(iface: &str) -> Result<(), IfaceError> {
    if !is_monitor(iface).await? {
        return Err(IfaceError::NotMonitor);
    }

    // bring interface down
    Command::new("ip")
        .args(["link", "set", "dev", iface, "down"])
        .output()
        .await
        .map_err(IfaceError::Io)?;

    let settings = crate::globals::State::get_settings();
    let mac_arg  = &settings.mac_address;

    let success = match mac_arg.as_str() {
        "random"  => {
            Command::new("macchanger")
                .args(["-A", iface])
                .output().await
                .map_err(IfaceError::Io)?
                .status.success()
        }
        "default" => {
            Command::new("macchanger")
                .args(["-p", iface])
                .output().await
                .map_err(IfaceError::Io)?
                .status.success()
        }
        mac => {
            Command::new("macchanger")
                .args(["-m", mac, iface])
                .output().await
                .map_err(IfaceError::Io)?
                .status.success()
        }
    };

    // bring interface back up
    Command::new("ip")
        .args(["link", "set", "dev", iface, "up"])
        .output()
        .await
        .map_err(IfaceError::Io)?;

    if success {
        info!("{}: MAC set to {}", iface, mac_arg);
        Ok(())
    } else {
        Err(IfaceError::BadMac)
    }
}

// ─────────────────────────────────────────────
// Network service management
// ─────────────────────────────────────────────

// Services that interfere with wireless card management
const INTERFERENCE_SERVICES: &[&str] = &[
    "wpa_supplicant",
    "NetworkManager",
    "wpa_action",
    "wpa_cli",
    "dhclient",
    "ifplugd",
    "dhcdbd",
    "dhcpcd",
    "udhcpc",
    "knetworkmanager",
    "avahi-autoipd",
    "avahi-daemon",
    "wlassistant",
    "wifibox",
    "wicd-daemon",
    "wicd-client",
    "iwd",
    "hostapd",
];

// Kill services that interfere with monitor mode
pub async fn kill_network_services() -> Result<(), IfaceError> {
    let settings = State::get_settings();
    if !settings.kill_network_manager { return Ok(()); }

    if !super::app::has_dep("systemctl") {
        return Err(IfaceError::NoSystemd);
    }

    for &service in INTERFERENCE_SERVICES {
        let running = Command::new("systemctl")
            .args(["is-active", service])
            .output()
            .await
            .map_err(IfaceError::Io)?;

        if running.status.success() {
            Command::new("systemctl")
                .args(["stop", service])
                .output()
                .await
                .map_err(IfaceError::Io)?;

            State::add_service_to_restore(service.to_string());
            warn!("stopped service: {}", service);
        }
    }

    Ok(())
}

// Restore previously killed services
pub async fn restore_network_services() -> Result<(), IfaceError> {
    let settings = State::get_settings();
    if !settings.kill_network_manager { return Ok(()); }

    if !super::app::has_dep("systemctl") {
        return Err(IfaceError::NoSystemd);
    }

    let services = State::take_services_to_restore();

    for service in &services {
        Command::new("systemctl")
            .args(["start", service])
            .output()
            .await
            .map_err(IfaceError::Io)?;

        info!("restored service: {}", service);
    }

    Ok(())
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_interfaces_no_panic() {
        // may return empty list but should not panic
        let _ = list_interfaces().await;
    }

    #[tokio::test]
    async fn test_is_monitor_nonexistent() {
        let result = is_monitor("nonexistent_iface_xyz").await;
        assert!(matches!(result, Err(IfaceError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_disable_monitor_not_monitor() {
        // loopback is never monitor - should return Ok
        let result = disable_monitor("lo").await;
        assert!(result.is_ok());
    }
}