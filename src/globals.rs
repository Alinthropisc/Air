use std::collections::HashMap;
use std::process::Child;
use std::sync::{Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;

use crate::types::*;






pub const APP_ID:      &str = "io.github.air";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION"); // из Cargo.toml

// ─────────────────────────────────────────────
// Filesystem paths
// ─────────────────────────────────────────────

pub const LIVE_SCAN_PATH:  &str = "/tmp/air_live_scan";
pub const OLD_SCAN_PATH:   &str = "/tmp/air_old_scan";
pub const MERGE_SCAN_PATH: &str = "/tmp/air_merge_scan";
pub const CONFIG_PATH:     &str = "/etc/air/config.toml";
pub const CAPTURE_DIR:     &str = "/tmp/air_captures";

// ─────────────────────────────────────────────
// Embedded icons
// ─────────────────────────────────────────────

pub const APP_ICON:     &[u8] = include_bytes!("../icons/app_icon.png");
pub const DEAUTH_ICON:  &[u8] = include_bytes!("../icons/deauth.png");
pub const STOP_ICON:    &[u8] = include_bytes!("../icons/stop.png");
pub const CAPTURE_ICON: &[u8] = include_bytes!("../icons/capture.png");

// ─────────────────────────────────────────────
// Type aliases for clarity
// ─────────────────────────────────────────────

// bssid → (AP, active attack processes)
pub type AttackPool = HashMap<String, AttackEntry>;

// ─────────────────────────────────────────────
// Global state - OnceLock instead of lazy_static
//
// RwLock for read-heavy data (AP list, vendors)
// Mutex for write-heavy or exclusive data (processes)
// ─────────────────────────────────────────────

// Current monitor interface name (e.g. "wlan0mon")
fn iface() -> &'static Mutex<Option<String>> {
    static IFACE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    IFACE.get_or_init(|| Mutex::new(None))
}

// Was interface already in monitor mode before we touched it?
fn iface_was_monitor() -> &'static Mutex<bool> {
    static WAS_MONITOR: OnceLock<Mutex<bool>> = OnceLock::new();
    WAS_MONITOR.get_or_init(|| Mutex::new(false))
}

// Background thread that periodically refreshes scan data
fn update_proc() -> &'static Mutex<Option<JoinHandle<bool>>> {
    static UPDATE: OnceLock<Mutex<Option<JoinHandle<bool>>>> = OnceLock::new();
    UPDATE.get_or_init(|| Mutex::new(None))
}

// airodump-ng process doing the actual scan
fn scan_proc() -> &'static Mutex<Option<Child>> {
    static SCAN: OnceLock<Mutex<Option<Child>>> = OnceLock::new();
    SCAN.get_or_init(|| Mutex::new(None))
}

// All discovered APs - RwLock because UI reads constantly
fn aps() -> &'static RwLock<HashMap<String, Ap>> {
    static APS: OnceLock<RwLock<HashMap<String, Ap>>> = OnceLock::new();
    APS.get_or_init(|| RwLock::new(HashMap::new()))
}

// Clients not linked to any known AP
fn unlinked_clients() -> &'static RwLock<HashMap<String, Client>> {
    static CLIENTS: OnceLock<RwLock<HashMap<String, Client>>> = OnceLock::new();
    CLIENTS.get_or_init(|| RwLock::new(HashMap::new()))
}

// Active deauth attacks - bssid → entry
fn attack_pool() -> &'static Mutex<AttackPool> {
    static POOL: OnceLock<Mutex<AttackPool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

// OUI vendor lookup cache - MAC prefix → vendor name
fn vendors_cache() -> &'static RwLock<HashMap<String, String>> {
    static VENDORS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    VENDORS.get_or_init(|| RwLock::new(HashMap::new()))
}

// User settings
fn settings() -> &'static Mutex<Settings> {
    static SETTINGS: OnceLock<Mutex<Settings>> = OnceLock::new();
    SETTINGS.get_or_init(|| Mutex::new(Settings::default()))
}

// New version available (from GitHub API check)
fn new_version() -> &'static Mutex<Option<String>> {
    static VERSION: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    VERSION.get_or_init(|| Mutex::new(None))
}

// System services we stopped (need to restore on exit)
fn services_to_restore() -> &'static Mutex<Vec<String>> {
    static SERVICES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    SERVICES.get_or_init(|| Mutex::new(Vec::new()))
}

// ─────────────────────────────────────────────
// Public accessor API
// Clean interface - no direct lock() calls in UI code
// ─────────────────────────────────────────────

use crate::AirError;

pub struct State;

impl State {
    // ── Interface ──────────────────────────────

    pub fn get_iface() -> Option<String> {
        iface().lock()
            .ok()
            .and_then(|g| g.clone())
    }

    pub fn set_iface(name: Option<String>) {
        if let Ok(mut g) = iface().lock() {
            *g = name;
        }
    }

    pub fn get_iface_was_monitor() -> bool {
        iface_was_monitor().lock()
            .map(|g| *g)
            .unwrap_or(false)
    }

    pub fn set_iface_was_monitor(val: bool) {
        if let Ok(mut g) = iface_was_monitor().lock() {
            *g = val;
        }
    }

    // ── APs ────────────────────────────────────

    // Get clone of all APs for display
    pub fn get_aps() -> HashMap<String, Ap> {
        aps().read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    // Get single AP by BSSID
    pub fn get_ap(bssid: &str) -> Option<Ap> {
        aps().read()
            .ok()
            .and_then(|g| g.get(bssid).cloned())
    }

    // Replace entire AP map (after scan parse)
    pub fn set_aps(new_aps: HashMap<String, Ap>) {
        if let Ok(mut g) = aps().write() {
            *g = new_aps;
        }
    }

    // Update single AP (e.g. handshake captured)
    pub fn update_ap(bssid: &str, ap: Ap) {
        if let Ok(mut g) = aps().write() {
            g.insert(bssid.to_string(), ap);
        }
    }

    pub fn ap_count() -> usize {
        aps().read()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    // Mark AP as having captured handshake
    pub fn mark_handshake(bssid: &str) {
        if let Ok(mut g) = aps().write() {
            if let Some(ap) = g.get_mut(bssid) {
                ap.handshake = true;
            }
        }
    }


    pub fn get_unlinked_clients() -> HashMap<String, Client> {
        unlinked_clients().read().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn set_unlinked_clients(clients: HashMap<String, Client>) {
        if let Ok(mut g) = unlinked_clients().write() {
            *g = clients;
        }
    }


    // Is this BSSID currently under attack?
    pub fn is_attacking(bssid: &str) -> bool {
        attack_pool().lock().map(|g| g.contains_key(bssid)).unwrap_or(false)
    }

    pub fn add_attack(bssid: String, entry: AttackEntry) {
        if let Ok(mut g) = attack_pool().lock() {
            g.insert(bssid, entry);
        }
    }

    pub fn remove_attack(bssid: &str) -> Option<AttackEntry> {
        attack_pool().lock().ok().and_then(|mut g| g.remove(bssid))
    }

    pub fn attack_count() -> usize {
        attack_pool().lock().map(|g| g.len()).unwrap_or(0)
    }


    pub fn set_scan_proc(child: Option<Child>) {
        if let Ok(mut g) = scan_proc().lock() {
            *g = child;
        }
    }

    pub fn is_scanning() -> bool {
        scan_proc().lock().map(|g| g.is_some()).unwrap_or(false)
    }

    // Stop scan process
    pub fn stop_scan() {
        if let Ok(mut g) = scan_proc().lock() {
            if let Some(mut child) = g.take() {
                let _ = child.kill();
            }
        }
    }


    pub fn lookup_vendor(mac_prefix: &str) -> Option<String> {
        vendors_cache().read().ok().and_then(|g| g.get(mac_prefix).cloned())
    }

    pub fn cache_vendor(mac_prefix: String, vendor: String) {
        if let Ok(mut g) = vendors_cache().write() {
            g.insert(mac_prefix, vendor);
        }
    }

    pub fn vendor_cache_size() -> usize {
        vendors_cache().read().map(|g| g.len()).unwrap_or(0)
    }


    pub fn get_settings() -> Settings {
        settings().lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn update_settings(new: Settings) {
        if let Ok(mut g) = settings().lock() {
            *g = new;
        }
    }

    pub fn update_settings_with<F: FnOnce(&mut Settings)>(f: F) {
        if let Ok(mut g) = settings().lock() {
            f(&mut g);
        }
    }


    pub fn get_new_version() -> Option<String> {
        new_version().lock()
            .ok()
            .and_then(|g| g.clone())
    }

    pub fn set_new_version(ver: Option<String>) {
        if let Ok(mut g) = new_version().lock() {
            *g = ver;
        }
    }

    pub fn has_update() -> bool {
        Self::get_new_version().is_some()
    }


    pub fn add_service_to_restore(name: String) {
        if let Ok(mut g) = services_to_restore().lock() {
            if !g.contains(&name) {
                g.push(name);
            }
        }
    }

    pub fn take_services_to_restore() -> Vec<String> {
        services_to_restore().lock().map(|mut g| std::mem::take(&mut *g)).unwrap_or_default()
    }


    // Stop everything gracefully
    pub fn shutdown() {
        // stop scan
        Self::stop_scan();

        // kill all attacks
        if let Ok(mut pool) = attack_pool().lock() {
            for (_, entry) in pool.iter_mut() {
                entry.clients.kill_all();
            }
            pool.clear();
        }
        tracing::info!("Air state shutdown complete");
    }
}


#[derive(Debug, Clone, Default)]
pub struct AppStats {
    pub ap_count: usize,
    pub client_count: usize,
    pub unlinked_count: usize,
    pub active_attacks: usize,
    pub vendor_cache_size: usize,
    pub is_scanning: bool,
    pub has_update: bool,
    pub iface: Option<String>,
}

impl AppStats {
    pub fn collect() -> Self {
        let aps = State::get_aps();
        let client_count = aps.values().map(|ap| ap.client_count()).sum();

        Self {
            ap_count: aps.len(),
            client_count,
            unlinked_count: State::get_unlinked_clients().len(),
            active_attacks: State::attack_count(),
            vendor_cache_size: State::vendor_cache_size(),
            is_scanning: State::is_scanning(),
            has_update: State::has_update(),
            iface: State::get_iface(),
        }
    }
}
































