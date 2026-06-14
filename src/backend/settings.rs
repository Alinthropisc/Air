use tracing::{debug, warn};
use crate::types::Settings;
use crate::globals::{State, CONFIG_PATH};


// ─────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum SettingsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("Config directory does not exist: {0}")]
    NoConfigDir(String),
}

// ─────────────────────────────────────────────
// Load / Save
// ─────────────────────────────────────────────

// Load settings from disk - use defaults if file missing
pub async fn load_settings() {
    let path = std::path::Path::new(CONFIG_PATH);

    if !path.exists() {
        debug!("no config file at {} - using defaults", CONFIG_PATH);
        return;
    }

    match tokio::fs::read_to_string(path).await {
        Ok(content) => {
            match toml::from_str::<Settings>(&content) {
                Ok(mut settings) => {
                    // disable kill_network_manager if systemctl missing
                    if settings.kill_network_manager
                        && !super::app::has_dep("systemctl")
                    {
                        warn!("systemctl not found - disabling kill_network_manager");
                        settings.kill_network_manager = false;
                    }
                    State::update_settings(settings);
                    debug!("settings loaded from {}", CONFIG_PATH);
                }
                Err(e) => {
                    warn!("settings parse failed: {} - using defaults", e);
                }
            }
        }
        Err(e) => {
            warn!("could not read settings: {} - using defaults", e);
        }
    }
}

// Save settings to disk
pub async fn save_settings(
    mut settings: Settings,
) -> Result<(), SettingsError> {
    // validate systemctl availability
    if settings.kill_network_manager
        && !super::app::has_dep("systemctl")
    {
        warn!("systemctl not found - disabling kill_network_manager");
        settings.kill_network_manager = false;
    }

    // ensure config directory exists
    if let Some(parent) = std::path::Path::new(CONFIG_PATH).parent()
        && !parent.exists() {
        tokio::fs::create_dir_all(parent).await
            .map_err(SettingsError::Io)?;
    }

    let toml = toml::to_string_pretty(&settings)
        .map_err(SettingsError::Serialize)?;

    tokio::fs::write(CONFIG_PATH, toml).await
        .map_err(SettingsError::Io)?;

    State::update_settings(settings);
    debug!("settings saved to {}", CONFIG_PATH);
    Ok(())
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let s = Settings::default();
        assert_eq!(s.mac_address, "random");
        assert!(s.display_hidden_ap);
        assert!(s.kill_network_manager);
    }

    #[test]
    fn test_settings_toml_roundtrip() {
        let original = Settings::default();
        let toml = toml::to_string_pretty(&original).unwrap();
        let parsed: Settings = toml::from_str(&toml).unwrap();
        assert_eq!(parsed.mac_address, original.mac_address);
        assert_eq!(parsed.display_hidden_ap, original.display_hidden_ap);
    }

    #[test]
    fn test_use_random_mac() {
        let s = Settings { mac_address: "random".into(), ..Default::default() };
        assert!(s.use_random_mac());

        let s2 = Settings { mac_address: "AA:BB:CC:DD:EE:FF".into(), ..Default::default() };
        assert!(!s2.use_random_mac());
    }

    #[tokio::test]
    async fn test_load_settings_no_file() {
        // should not panic even with no config file
        load_settings().await;
    }
}