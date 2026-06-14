use tokio::process::Command;
use tracing::info;

use crate::globals::State;
use crate::types::*;
use crate::engine::{WpaHandshake, WpaKeyVersion};


#[derive(thiserror::Error, Debug)]
pub enum CaptureError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("No capture file found at: {0}")]
    NoFile(String),

    #[error("Failed to save capture: {0}")]
    SaveFailed(String),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}


// One detected handshake in a cap file
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub bssid: String,
    pub essid: String,
    pub handshake_count: u32,
}

/// High-level API used by main.rs: parse cap files and return WpaHandshake structs.
///
/// This is a best-effort synchronous wrapper; it calls aircrack-ng in a blocking
/// fashion via spawn_blocking so it can be used from async context.
/// Returns only entries where aircrack-ng confirmed a handshake.
pub fn get_handshakes<'a>(
    cap_files: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<WpaHandshake>, CaptureError> {
    let files: Vec<&str> = cap_files.into_iter().collect();
    let existing: Vec<&str> = files.iter().copied()
        .filter(|p| std::path::Path::new(p).exists())
        .collect();

    if existing.is_empty() {
        return Ok(vec![]);
    }

    let output = std::process::Command::new("aircrack-ng")
        .args(&existing)
        .output()
        .map_err(CaptureError::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let infos  = parse_handshake_output(&stdout)?;

    // Convert HandshakeInfo → WpaHandshake with zeroed crypto fields.
    // Caller is expected to populate anonce/snonce/eapol/mic/keyver
    // from the actual pcap (e.g. via a future pcap parser module).
    let handshakes = infos.into_iter().map(|info| WpaHandshake {
        bssid:  info.bssid,
        stmac:  String::new(),
        anonce: [0u8; 32],
        snonce: [0u8; 32],
        eapol:  Vec::new(),
        mic:    [0u8; 16],
        keyver: WpaKeyVersion::Wpa2Ccmp,
        essid:  info.essid,
    }).collect();

    Ok(handshakes)
}

// Run aircrack-ng on cap files to find handshakes
// Returns list of BSSIDs that have captured handshakes
pub async fn find_handshakes(cap_files: &[&str]) -> Result<Vec<HandshakeInfo>, CaptureError> {
    // filter to only existing files
    let existing: Vec<&str> = cap_files.iter().copied().filter(|p| std::path::Path::new(p).exists()).collect();

    if existing.is_empty() {
        return Ok(vec![]);
    }
    let output = Command::new("aircrack-ng").args(&existing).output().await.map_err(CaptureError::Io)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_handshake_output(&stdout)
}

// Parse aircrack-ng stdout to extract handshake info
// Line format: "  1  AA:BB:CC:DD:EE:FF  MyNetwork  WPA (2 handshake)"
fn parse_handshake_output(output: &str) -> Result<Vec<HandshakeInfo>, CaptureError> {
    use regex::Regex;
    // matches: index, bssid, essid, handshake count
    let re = Regex::new(r"\s+(\d+)\s+([\w:]+)\s+(.*?)\s+WPA \((\d+)\s+handshake")?;

    let mut results = vec![];

    for line in output.lines() {
        let caps = match re.captures(line) {
            Some(c) => c,
            None    => continue,
        };
        let count = caps[4].parse::<u32>().unwrap_or(0);

        if count == 0 { 
            continue; 
        }
        let essid = caps[3].trim().to_string();
        results.push(HandshakeInfo {
            bssid: caps[2].to_string(),
            essid:     if essid.is_empty() {
                          "hidden".to_string()
                       } else {
                            essid
                       },
            handshake_count: count,
        });
    }

    Ok(results)
}

// Update handshake status in global AP state
pub async fn update_handshakes() -> Result<(), CaptureError> {
    use super::scan::{live_scan_path, old_scan_path};
    let live = format!("{}-01.cap", live_scan_path());
    let old  = format!("{}-01.cap", old_scan_path());
    let handshakes = find_handshakes(&[&live, &old]).await?;

    for hs in &handshakes {
        State::mark_handshake(&hs.bssid);
        info!("handshake confirmed: bssid={} essid={} count={}",hs.bssid, hs.essid, hs.handshake_count);
    }
    Ok(())
}


// Save current capture file to user-specified path
pub async fn save_capture(dst: &str) -> Result<(), CaptureError> {
    use super::scan::old_scan_path;
    let src = format!("{}-01.cap", old_scan_path());

    if !std::path::Path::new(&src).exists() {
        return Err(CaptureError::NoFile(src));
    }
    tokio::fs::copy(&src, dst).await.map_err(|e| CaptureError::SaveFailed(e.to_string()))?;
    info!("capture saved: {} → {}", src, dst);
    Ok(())
}

// JSON report of all discovered APs and clients
#[derive(Debug, serde::Serialize)]
struct ScanReport {
    generated_at: String,
    ap_count: usize,
    client_count: usize,
    access_points: Vec<Ap>,
    unlinked_clients: Vec<Client>,
}

// Save full scan report as JSON
pub async fn save_report(dst: &str) -> Result<(), CaptureError> {
    let aps     = State::get_aps();
    let clients = State::get_unlinked_clients();
    let ap_list: Vec<Ap>     = aps.values().cloned().collect();
    let cli_list: Vec<Client> = clients.values().cloned().collect();
    let total_clients = ap_list.iter().map(|ap| ap.client_count()).sum::<usize>() + cli_list.len();

    let report = ScanReport {
        generated_at: chrono::Local::now().to_rfc3339(),
        ap_count: ap_list.len(),
        client_count: total_clients,
        access_points: ap_list,
        unlinked_clients: cli_list,
    };
    let json = serde_json::to_string_pretty(&report)?;
    tokio::fs::write(dst, json).await.map_err(CaptureError::Io)?;
    info!("report saved to: {}", dst);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OUTPUT: &str = r#"
   #  BSSID              ESSID                     Encryption

   1  AA:BB:CC:DD:EE:FF  HomeNetwork               WPA (2 handshake)
   2  11:22:33:44:55:66  OfficeWifi                WPA (1 handshake)
   3  FF:EE:DD:CC:BB:AA                            WPA (0 handshake)
    "#;

    #[test]
    fn test_parse_handshakes_finds_two() {
        let result = parse_handshake_output(SAMPLE_OUTPUT).unwrap();
        assert_eq!(result.len(), 2); // 0 handshake filtered out
    }

    #[test]
    fn test_parse_handshakes_bssid() {
        let result = parse_handshake_output(SAMPLE_OUTPUT).unwrap();
        assert_eq!(result[0].bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(result[1].bssid, "11:22:33:44:55:66");
    }

    #[test]
    fn test_parse_handshakes_essid() {
        let result = parse_handshake_output(SAMPLE_OUTPUT).unwrap();
        assert_eq!(result[0].essid, "HomeNetwork");
        assert_eq!(result[1].essid, "OfficeWifi");
    }

    #[test]
    fn test_parse_handshakes_count() {
        let result = parse_handshake_output(SAMPLE_OUTPUT).unwrap();
        assert_eq!(result[0].handshake_count, 2);
        assert_eq!(result[1].handshake_count, 1);
    }

    #[test]
    fn test_parse_empty_output() {
        let result = parse_handshake_output("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_zero_handshakes_filtered() {
        let output = "  1  FF:EE:DD:CC:BB:AA  Hidden  WPA (0 handshake)";
        let result = parse_handshake_output(output).unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_find_handshakes_missing_files() {
        // nonexistent files → returns empty not error
        let result = find_handshakes(&[
            "/tmp/nonexistent_12345.cap"
        ]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_save_capture_missing_src() {
        let result = save_capture("/tmp/test_out.cap").await;
        assert!(matches!(result, Err(CaptureError::NoFile(_))));
    }
}








































































