use std::time::SystemTime;
use std::process::Child;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};



#[derive(Debug, Clone, Default)]
pub struct CharsetParams {
    pub lowercase: bool, // a-z
    pub uppercase: bool, // A-Z
    pub numbers: bool, // 0-9
    pub symbols: bool, // @!#$%^&*
}


// Which clients to attack during deauth
pub enum AttackedClients {
    // Broadcast deauth kill all clients at once
    All(Child),
    // Targeted deauth (mac, procress), pairs
    Selected(Vec<(String, Child)>)
}

// Tool used for deauth attacks
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackTool {
    Aireplay, // classic deauth via aireplay-ng
    Mdk4, // more aggressive, bypasses some filters
}

impl AttackedClients {
    // kill all running attack processes
    pub fn kill_all(&mut self) {
        match self {
            Self::All(child) => {
                let _ = child.kill();
            }
            Self::Selected(list) => {
                for (_, child) in list.iter_mut() {
                    let _ = child.kill();
                }
            }
        }
    }

    // count of active attack processes
    pub fn count(&self) -> usize {
        match self {
            Self::All(_) => 1,
            Self::Selected(list) => list.len(),
        }
    }
}



impl AttackTool {
    pub fn binary_name(&self) -> &'static str {
        match self {
            Self::Aireplay => "aireplay-ng",
            Self::Mdk4 => "Mdk4",
        }
    }
}


impl std::fmt::Display for AttackTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.binary_name())
    }
}




impl CharsetParams {
    // Build actual charset string from params
    pub fn build(&self) -> String {
        let mut charset = String::new();

        if self.lowercase { 
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
        
        if self.uppercase { 
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        
        if self.numbers { 
            charset.push_str("0123456789");
        }

        if self.symbols { 
            charset.push_str("!@#$%^&*()-_=+[]{}|;:,.<>?");
        }
        charset
    }

    pub fn is_empty(&self) -> bool {
        !self.lowercase && !self.uppercase && !self.numbers && !self.symbols
    }
}






impl BruteforceCharset {
    pub fn to_string(&self) -> String {
        match self {
            Self::Params(p) => p.build(),
            Self::Custom(s) => s.clone(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.to_string().is_empty()
    }
}


// WiFi security types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Privacy {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Unknown(String),
}

impl Privacy {
    pub fn from_str(s: &str) -> Self {
        let upper = s.to_uppercase();

        if upper.contains("WPA3") { 
            Self::Wpa3
        } else if upper.contains("WPA2") { 
            Self::Wpa2
        } else if upper.contains("WPA") { 
            Self::Wpa
        } else if upper.contains("WEP") { 
            Self::Wep
        } else if upper == "OPN" || upper.is_empty() { 
            Self::Open
        } else { 
            Self::Unknown(s.to_string())
        }
    }

    pub fn is_crackable(&self) -> bool {
        matches!(self, Self::Wpa | Self::Wpa2 | Self::Wep)
    }
}

impl std::fmt::Display for Privacy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "OPN"),
            Self::Wep => write!(f, "WEP"),
            Self::Wpa => write!(f, "WPA"),
            Self::Wpa2 => write!(f, "WPA2"),
            Self::Wpa3 => write!(f, "WPA3"),
            Self::Unknown(s) => write!(f, "{}", s),
        }
    }
}

// Access Point - WiFi network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ap {
    // Identity
    pub essid: String, // network name (may be empty if hidden)
    pub bssid: String, // MAC address of AP
    // Radio
    pub band: String, // 2.4GHz / 5GHz / 6GHz
    pub channel: u8, // 1-14 (2.4) or 36-177 (5GHz)
    pub speed: String, // link speed Mbps
    // Signal
    pub power: i32, // dBm (negative, closer to 0 = stronger)
    // Security
    pub privacy: Privacy,
    // State
    pub hidden: bool, // ESSID not broadcast
    pub handshake: bool, // captured handshake in session
    pub saved_handshake: Option<String>,// path to saved .cap file
    // Timing
    pub first_seen: String,
    pub last_seen:  String,
    // Connected clients
    pub clients: HashMap<String, Client>, // mac → client
}

impl Ap {
    // Signal strength as human-readable quality
    pub fn signal_quality(&self) -> &'static str {
        match self.power {
            p if p >= -50 => "Excellent",
            p if p >= -60 => "Good",
            p if p >= -70 => "Fair",
            p if p >= -80 => "Weak",
            _ => "Very Weak",
        }
    }

    pub fn is_hidden(&self) -> bool {
        self.hidden || self.essid.is_empty()
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    // Can we attempt to crack this AP?
    pub fn is_target_ready(&self) -> bool {
        self.privacy.is_crackable() && self.handshake
    }
}

// Station (client device) connected to AP
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Client {
    pub mac: String, // MAC address
    pub packets: u64,    // packet count
    pub power: i32,    // signal dBm
    pub first_seen: String,
    pub last_seen: String,
    pub vendor: String, // OUI lookup result
    pub probes: String, // SSIDs this client probes for
}

impl Client {
    pub fn display_name(&self) -> String {
        if self.vendor.is_empty() {
            self.mac.clone()
        } else {
            format!("{} ({})", self.mac, self.vendor)
        }
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    // MAC address for monitor interface ("random" or specific)
    pub mac_address: String,

    // Show APs with hidden ESSID in list
    pub display_hidden_ap: bool,

    // Kill NetworkManager before scanning (avoids interference)
    pub kill_network_manager: bool,

    // Auto-save captured handshakes
    pub auto_save_handshakes: bool,

    // Directory for saved handshakes
    pub handshake_dir: String,

    // Default attack tool
    pub default_attack_tool: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mac_address: "random".to_string(),
            display_hidden_ap: true,
            kill_network_manager: true,
            auto_save_handshakes: true,
            handshake_dir: "/tmp/air_captures".to_string(),
            default_attack_tool: "aireplay-ng".to_string(),
        }
    }
}

impl Settings {
    pub fn use_random_mac(&self) -> bool {
        self.mac_address.to_lowercase() == "random"
    }
}


// One active attack against an AP
pub struct AttackEntry {
    pub ap:      Ap,
    pub clients: AttackedClients,
    pub tool:    AttackTool,
    pub started: SystemTime,
}

impl AttackEntry {
    pub fn new(ap: Ap, clients: AttackedClients, tool: AttackTool) -> Self {
        Self {
            ap,
            clients,
            tool,
            started: SystemTime::now(),
        }
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().map(|d| d.as_secs()).unwrap_or(0)
    }
}























