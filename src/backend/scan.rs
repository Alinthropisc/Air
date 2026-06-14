use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command as AsyncCmd;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::globals::State;
use crate::types::*;


#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("No band selected - choose 2.4GHz or 5GHz")]
    NoBand,

    #[error("Invalid channel filter: '{0}'")]
    BadChannelFilter(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Signal error: {0}")]
    Signal(String),
}



#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub interface: String,
    pub band_2_4: bool,
    pub band_5: bool,
    pub channel_filter: Option<Vec<u8>>,  // specific channels
    pub write_interval: u32,               // seconds
}

impl ScanConfig {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            band_2_4: true,
            band_5: false,
            channel_filter: None,
            write_interval: 1,
        }
    }

    pub fn with_5ghz(mut self) -> Self {
        self.band_5 = true;
        self
    }

    pub fn with_channels(mut self, channels: Vec<u8>) -> Self {
        self.channel_filter = Some(channels);
        self
    }

    // Build band string for airodump-ng --band flag
    fn band_string(&self) -> Result<String, ScanError> {
        if !self.band_2_4 && !self.band_5 {
            return Err(ScanError::NoBand);
        }
        let mut band = String::new();

        if self.band_5   { 
            band.push('a');
        }

        if self.band_2_4 { 
            band.push_str("bg");
        }
        Ok(band)
    }
}




// Start airodump-ng scan
pub async fn start_scan(config: ScanConfig) -> Result<(), ScanError> {
    // stop any existing scan first
    stop_scan().await.ok();

    let band = config.band_string()?;
    let live_path = live_scan_path();

    let mut args = vec![
        config.interface.clone(),
        "-a".into(),
        "--output-format".into(), "csv,cap".into(),
        "-w".into(), live_path.clone(),
        "--write-interval".into(), config.write_interval.to_string(),
        "--band".into(), band,
    ];

    if let Some(channels) = &config.channel_filter {
        validate_channels(channels)?;
        let ch_str = channels.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        args.push("--channel".into());
        args.push(ch_str);
    }
    info!("starting scan: {:?}", config);
    // std::process::Command — fire-and-forget; result tracked in State.
    let child = std::process::Command::new("airodump-ng")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ScanError::Io)?;

    State::set_scan_proc(Some(child));
    Ok(())
}

// Stop airodump-ng and merge captures
pub async fn stop_scan() -> Result<(), ScanError> {
    State::stop_scan();

    let live_cap  = format!("{}-01.cap", live_scan_path());
    let live_csv  = format!("{}-01.csv", live_scan_path());
    let old_cap   = format!("{}-01.cap", old_scan_path());
    let merge_cap = format!("{}-01.cap", merge_scan_path());

    // remove csv - not needed after scan
    tokio::fs::remove_file(&live_csv).await.ok();

    let live_exists = Path::new(&live_cap).exists();
    let old_exists  = Path::new(&old_cap).exists();

    if !live_exists {
        return Ok(());
    }

    if !old_exists {
        // first scan - just rename
        tokio::fs::rename(&live_cap, &old_cap).await.ok();
        return Ok(());
    }

    // merge live + old captures
    let status = AsyncCmd::new("mergecap")
        .args(["-a", "-F", "pcap", "-w", &merge_cap, &old_cap, &live_cap])
        .status()
        .await
        .map_err(ScanError::Io)?;

    tokio::fs::remove_file(&live_cap).await.ok();
    tokio::fs::remove_file(&old_cap).await.ok();

    if status.success() {
        tokio::fs::rename(&merge_cap, &old_cap).await.ok();
    }

    info!("scan stopped, captures merged");
    Ok(())
}

// ─────────────────────────────────────────────
// Live data parsing
// ─────────────────────────────────────────────

// Raw CSV rows from airodump
#[derive(Debug, serde::Deserialize)]
struct RawAp {
    #[serde(rename = "BSSID")]            bssid:      String,
    #[serde(rename = " First time seen")] first_seen: String,
    #[serde(rename = " Last time seen")]  last_seen:  String,
    #[serde(rename = " channel")]         channel:    String,
    #[serde(rename = " Speed")]           speed:      String,
    #[serde(rename = " Privacy")]         privacy:    String,
    #[serde(rename = " Power")]           power:      String,
    #[serde(rename = " ID-length")]       id_length:  String,
    #[serde(rename = " ESSID")]           essid:      String,
    // ignored fields
    #[serde(rename = " Cipher")]          _cipher:    String,
    #[serde(rename = " Authentication")]  _auth:      String,
    #[serde(rename = " # beacons")]       _beacons:   String,
    #[serde(rename = " # IV")]            _iv:        String,
    #[serde(rename = " LAN IP")]          _lan_ip:    String,
    #[serde(rename = " Key")]             _key:       String,
}

#[derive(Debug, serde::Deserialize)]
struct RawClient {
    #[serde(rename = "Station MAC")]      mac:        String,
    #[serde(rename = " First time seen")] first_seen: String,
    #[serde(rename = " Last time seen")]  last_seen:  String,
    #[serde(rename = " Power")]           power:      String,
    #[serde(rename = " # packets")]       packets:    String,
    #[serde(rename = " BSSID")]           bssid:      String,
    #[serde(rename = " Probed ESSIDs")]   probes:     String,
}

// Parse airodump CSV and update global state
// Called periodically by update loop
pub async fn parse_scan_data() -> HashMap<String, Ap> {
    let csv_path = format!("{}-01.csv", live_scan_path());

    let csv = match tokio::fs::read_to_string(&csv_path).await {
        Ok(s)  => s,
        Err(_) => return State::get_aps(),
    };

    // airodump CSV has two sections separated by blank line
    let parts: Vec<&str> = csv.split("\r\n\r\n").collect();
    let ap_csv  = parts.first().copied().unwrap_or("");
    let cli_csv = parts.get(1).copied().unwrap_or("");

    let mut aps = State::get_aps();

    // parse access points
    let mut ap_reader = csv::Reader::from_reader(ap_csv.as_bytes());
    for raw in ap_reader.deserialize::<RawAp>().flatten() {
        let ap = parse_raw_ap(raw, &aps);
        aps.insert(ap.bssid.clone(), ap);
    }

    // parse clients and link to APs
    let mut unlinked: HashMap<String, Client> = HashMap::new();
    let mut cli_reader = csv::Reader::from_reader(cli_csv.as_bytes());

    for raw in cli_reader.deserialize::<RawClient>().flatten() {
        let mac    = raw.mac.trim().to_string();
        let vendor = super::vendors::lookup_vendor(&mac);

        let client = Client {
            mac:        mac.clone(),
            packets:    raw.packets.trim().parse().unwrap_or(0),
            power:      raw.power.trim().parse().unwrap_or(-100),
            first_seen: raw.first_seen.trim().to_string(),
            last_seen:  raw.last_seen.trim().to_string(),
            vendor,
            probes:     raw.probes.trim().to_string(),
        };

        let ap_bssid = raw.bssid.trim();
        if let Some(ap) = aps.get_mut(ap_bssid) {
            ap.clients.insert(mac, client);
        } else {
            unlinked.insert(mac, client);
        }
    }
    State::set_aps(aps.clone());
    State::set_unlinked_clients(unlinked);

    aps
}

fn parse_raw_ap(raw: RawAp, existing: &HashMap<String, Ap>) -> Ap {
    let bssid   = raw.bssid.trim().to_string();
    let channel = raw.channel.trim().parse::<u8>().unwrap_or(0);
    let band    = if channel > 14 { "5 GHz" } else { "2.4 GHz" };

    let (essid, hidden) = if raw.essid.trim().is_empty() {
        let len = raw.id_length.trim();
        let placeholder = format!("[Hidden] len={}", len);
        // preserve real essid if we discovered it before
        let real = existing.get(&bssid)
            .filter(|ap| !ap.is_hidden())
            .map(|ap| ap.essid.clone())
            .unwrap_or(placeholder);
        (real, true)
    } else {
        (raw.essid.trim().to_string(), false)
    };

    let privacy_str = raw.privacy.split_whitespace().next().unwrap_or("OPN");
    let privacy = Privacy::from_str(privacy_str);
    // preserve handshake status from existing data
    let old = existing.get(&bssid);
    let handshake       = old.map(|a| a.handshake).unwrap_or(false);
    let saved_handshake = old.and_then(|a| a.saved_handshake.clone());
    let first_seen      = old
        .map(|a| a.first_seen.clone())
        .unwrap_or_else(|| raw.first_seen.trim().to_string());
    let clients         = old.map(|a| a.clients.clone()).unwrap_or_default();

    Ap {
        essid,
        bssid,
        band: band.to_string(),
        channel,
        speed:   raw.speed.trim().to_string(),
        power:   raw.power.trim().parse().unwrap_or(-100),
        privacy,
        hidden,
        handshake,
        saved_handshake,
        first_seen,
        last_seen: raw.last_seen.trim().to_string(),
        clients,
    }
}

// Background task: refresh scan data every second
pub fn spawn_update_loop() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;

            if !State::is_scanning() {
                break;
            }
            parse_scan_data().await;
            super::capture::update_handshakes().await.ok();
            super::vendors::update_all_vendors().await;
            debug!("scan data refreshed: {} APs", State::ap_count());
        }
    })
}


fn validate_channels(channels: &[u8]) -> Result<(), ScanError> {
    for &ch in channels {
        let valid = (1..=14).contains(&ch) || (36..=177).contains(&ch);
        if !valid {
            return Err(ScanError::BadChannelFilter(ch.to_string()));
        }
    }
    Ok(())
}

pub fn live_scan_path() -> String {
    format!("/tmp/air_live_{}", std::process::id())
}

pub fn old_scan_path() -> String {
    format!("/tmp/air_old_{}", std::process::id())
}

pub fn merge_scan_path() -> String {
    format!("/tmp/air_merge_{}", std::process::id())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_band_string_both() {
        let cfg = ScanConfig::new("wlan0").with_5ghz();
        assert_eq!(cfg.band_string().unwrap(), "abg");
    }

    #[test]
    fn test_band_string_2_4_only() {
        let cfg = ScanConfig::new("wlan0");
        assert_eq!(cfg.band_string().unwrap(), "bg");
    }

    #[test]
    fn test_band_string_none_fails() {
        let mut cfg = ScanConfig::new("wlan0");
        cfg.band_2_4 = false;
        cfg.band_5   = false;
        assert!(matches!(cfg.band_string(), Err(ScanError::NoBand)));
    }

    #[test]
    fn test_validate_channels_ok() {
        assert!(validate_channels(&[1, 6, 11, 36, 149]).is_ok());
    }

    #[test]
    fn test_validate_channels_bad() {
        assert!(validate_channels(&[0]).is_err());
        assert!(validate_channels(&[15]).is_err());
        assert!(validate_channels(&[200]).is_err());
    }

    #[test]
    fn test_parse_raw_ap_hidden() {
        let raw = RawAp {
            bssid:      "AA:BB:CC:DD:EE:FF".to_string(),
            first_seen: "2024-01-01".to_string(),
            last_seen:  "2024-01-01".to_string(),
            channel:    " 6".to_string(),
            speed:      " 54".to_string(),
            privacy:    " WPA2".to_string(),
            power:      " -60".to_string(),
            id_length:  " 8".to_string(),
            essid:      "".to_string(),
            _cipher:    "".to_string(),
            _auth:      "".to_string(),
            _beacons:   "".to_string(),
            _iv:        "".to_string(),
            _lan_ip:    "".to_string(),
            _key:       "".to_string(),
        };
        let ap = parse_raw_ap(raw, &HashMap::new());
        assert!(ap.hidden);
        assert!(ap.essid.starts_with("[Hidden]"));
    }

    #[test]
    fn test_parse_raw_ap_power() {
        let raw = RawAp {
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            first_seen: "".to_string(),
            last_seen: "".to_string(),
            channel: " 6".to_string(),
            speed: " 54".to_string(),
            privacy: " WPA2".to_string(),
            power: " -72".to_string(),
            id_length: " 4".to_string(),
            essid: " MyNet".to_string(),
            _cipher: "".to_string(),
            _auth: "".to_string(),
            _beacons: "".to_string(),
            _iv: "".to_string(),
            _lan_ip: "".to_string(),
            _key: "".to_string(),
        };
        let ap = parse_raw_ap(raw, &HashMap::new());
        assert_eq!(ap.power, -72);
        assert_eq!(ap.signal_quality(), "Fair");
    }
}































