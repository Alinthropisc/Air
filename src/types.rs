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






/// Source of the character set for bruteforce
#[derive(Debug, Clone)]
pub enum BruteforceCharset {
    /// Built from checkbox flags
    Params(CharsetParams),
    /// Raw custom string
    Custom(String),
}

impl BruteforceCharset {
    pub fn is_valid(&self) -> bool {
        !self.to_string().is_empty()
    }
}

impl std::fmt::Display for BruteforceCharset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Params(p) => p.build(),
            Self::Custom(s) => s.clone(),
        };
        write!(f, "{}", s)
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
    #[allow(clippy::should_implement_trait)]
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

impl Default for Ap {
    fn default() -> Self {
        Self {
            essid:          String::new(),
            bssid:          String::new(),
            band:           "2.4 GHz".to_string(),
            channel:        0,
            speed:          String::new(),
            power:          -100,
            privacy:        Privacy::Unknown(String::new()),
            hidden:         false,
            handshake:      false,
            saved_handshake: None,
            first_seen:     String::new(),
            last_seen:      String::new(),
            clients:        std::collections::HashMap::new(),
        }
    }
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

// ── Event bus ─────────────────────────────────────────────────────────────────

/// Application-wide events broadcast to all TUI/log subscribers via tokio::broadcast.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// A new AP appeared in the scan
    ApDiscovered(Box<Ap>),
    /// An existing AP's data changed (signal, clients, handshake flag)
    ApUpdated(String),
    /// 4-way handshake captured for this BSSID
    HandshakeCaptured(String),
    /// Live crack stats (emitted every ~5 000 candidates)
    CrackProgress(CrackProgress),
    /// Cracking succeeded
    CrackFound { bssid: String, essid: String, password: String },
    /// Wordlist/bruteforce exhausted without a match
    CrackExhausted { bssid: String, tried: u64 },
    /// Human-readable log line
    Log(LogLevel, String),
}

// ── Log ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel { Info, Warn, Error, Success }

/// One entry in the in-memory log ring buffer shown in the Log tab.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level:   LogLevel,
    pub message: String,
    pub ts:      chrono::DateTime<chrono::Local>,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self { level, message: message.into(), ts: chrono::Local::now() }
    }

    pub fn ts_str(&self) -> String {
        self.ts.format("%H:%M:%S").to_string()
    }

    pub fn prefix(&self) -> &'static str {
        match self.level {
            LogLevel::Info    => "INFO ",
            LogLevel::Warn    => "WARN ",
            LogLevel::Error   => "ERR  ",
            LogLevel::Success => "OK   ",
        }
    }
}

// ── Crack progress ─────────────────────────────────────────────────────────────

/// Live statistics for an in-progress crack — broadcast every ~5 000 candidates.
#[derive(Debug, Clone, Default)]
pub struct CrackProgress {
    pub bssid:     String,
    pub essid:     String,
    pub tried:     u64,
    pub total:     u64,     // 0 = unknown (bruteforce without pre-count)
    pub speed_wps: f64,     // words per second (rolling window)
    pub eta_secs:  Option<u64>,
    pub state:     CrackState,
}

impl CrackProgress {
    pub fn percent(&self) -> f64 {
        if self.total == 0 { return 0.0; }
        (self.tried as f64 / self.total as f64 * 100.0).min(100.0)
    }

    pub fn eta_display(&self) -> String {
        match self.eta_secs {
            None       => "∞".to_string(),
            Some(s) if s < 60    => format!("{s}s"),
            Some(s) if s < 3600  => format!("{}m {:02}s", s / 60, s % 60),
            Some(s)              => format!("{}h {:02}m", s / 3600, (s % 3600) / 60),
        }
    }

    pub fn speed_display(&self) -> String {
        if self.speed_wps < 1_000.0 {
            format!("{:.0} w/s", self.speed_wps)
        } else if self.speed_wps < 1_000_000.0 {
            format!("{:.1}k w/s", self.speed_wps / 1_000.0)
        } else {
            format!("{:.2}M w/s", self.speed_wps / 1_000_000.0)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrackState {
    #[default]
    Idle,
    Running,
    Found,
    Exhausted,
    Stopped,
}

impl std::fmt::Display for CrackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle      => write!(f, "idle"),
            Self::Running   => write!(f, "running"),
            Self::Found     => write!(f, "FOUND"),
            Self::Exhausted => write!(f, "exhausted"),
            Self::Stopped   => write!(f, "stopped"),
        }
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























