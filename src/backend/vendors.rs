use tracing::debug;
use crate::globals::State;


// vendors.rs generated at build time from OUI database
// build.rs downloads/parses the IEEE OUI list
include!(concat!(env!("OUT_DIR"), "/vendors.rs"));
// expands to: static VENDORS: phf::Map<&str, &str> = phf_map! { ... };

// ─────────────────────────────────────────────
// Lookup
// ─────────────────────────────────────────────

// Look up vendor for a MAC address
// Tries progressively shorter prefixes
// AA:BB:CC:DD:EE:FF → try AA:BB:CC:DD:EE → AA:BB:CC:DD → etc
pub fn lookup_vendor(mac: &str) -> String {
    // check cache first
    let prefix = mac_prefix(mac);
    if let Some(cached) = State::lookup_vendor(&prefix)
        && !cached.is_empty() {
        return cached;
    }

    // cache miss - look up in OUI table
    let vendor = find_in_oui(mac);
    State::cache_vendor(prefix, vendor.clone());
    vendor
}

// Search OUI table with progressively shorter prefixes
fn find_in_oui(mac: &str) -> String {
    // normalize: uppercase, no colons
    let normalized: String = mac
        .to_uppercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();

    if normalized.len() < 6 {
        return "Unknown".to_string();
    }

    // try from longest prefix (12 chars) down to 6 chars
    let mut prefix = normalized[..12.min(normalized.len())].to_string();

    while prefix.len() >= 6 {
        if let Some(&vendor) = VENDORS.get(prefix.as_str()) {
            return vendor.to_string();
        }
        prefix.pop();
    }

    "Unknown".to_string()
}

// Extract prefix key for caching (first 8 chars of normalized MAC)
fn mac_prefix(mac: &str) -> String {
    mac.to_uppercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(8)
        .collect()
}

// ─────────────────────────────────────────────
// Batch update
// ─────────────────────────────────────────────

// Update vendor info for all MACs in current AP list
// Called periodically by scan update loop
pub async fn update_all_vendors() {
    let aps = State::get_aps();

    for ap in aps.values() {
        for mac in ap.clients.keys() {
            let prefix = mac_prefix(mac);
            // only look up if not cached yet
            if State::lookup_vendor(&prefix).is_none() {
                let vendor = find_in_oui(mac);
                State::cache_vendor(prefix, vendor);
            }
        }
    }

    let unlinked = State::get_unlinked_clients();
    for mac in unlinked.keys() {
        let prefix = mac_prefix(mac);
        if State::lookup_vendor(&prefix).is_none() {
            let vendor = find_in_oui(mac);
            State::cache_vendor(prefix, vendor);
        }
    }

    debug!(
        "vendors updated: {} cached",
        State::vendor_cache_size()
    );
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_prefix_extraction() {
        let prefix = mac_prefix("AA:BB:CC:DD:EE:FF");
        assert_eq!(prefix, "AABBCCDD");
    }

    #[test]
    fn test_mac_prefix_short() {
        let prefix = mac_prefix("AA:BB");
        assert_eq!(prefix, "AABB");
    }

    #[test]
    fn test_find_oui_unknown() {
        // random test MAC - probably unknown
        let result = find_in_oui("FF:FF:FF:FF:FF:FF");
        // should return something (Unknown or actual vendor)
        assert!(!result.is_empty());
    }

    #[test]
    fn test_find_oui_too_short() {
        let result = find_in_oui("AA:BB");
        assert_eq!(result, "Unknown");
    }

    #[test]
    fn test_lookup_vendor_cached() {
        // first call
        let v1 = lookup_vendor("AA:BB:CC:DD:EE:FF");
        // second call should hit cache
        let v2 = lookup_vendor("AA:BB:CC:DD:EE:FF");
        assert_eq!(v1, v2);
    }

    #[tokio::test]
    async fn test_update_all_vendors_empty_state() {
        // should not panic with empty AP list
        update_all_vendors().await;
    }
}