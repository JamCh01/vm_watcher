//! Load and validate `config.toml`. The program refuses to start on any validation error,
//! always naming the offending value.

use std::path::Path;

use serde::Deserialize;

use crate::ip_range::{validate_ranges, IpRange};

/// Detail-page column ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    Ip,
    Rx,
    Tx,
    Total,
}

impl SortMode {
    pub fn next(self) -> SortMode {
        match self {
            SortMode::Ip => SortMode::Rx,
            SortMode::Rx => SortMode::Tx,
            SortMode::Tx => SortMode::Total,
            SortMode::Total => SortMode::Ip,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortMode::Ip => "IP",
            SortMode::Rx => "RX",
            SortMode::Tx => "TX",
            SortMode::Total => "RX+TX",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network: NetworkConfig,
    #[serde(default)]
    pub collector: CollectorConfig,
    #[serde(default)]
    pub display: DisplayConfig,
    #[serde(default, rename = "ip_ranges")]
    pub ip_ranges: Vec<IpRangeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub bridge: String,
}

fn default_refresh_interval_ms() -> u64 {
    1000
}

fn default_scan_interval_secs() -> u64 {
    5
}

fn default_map_max_entries() -> u32 {
    8192
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    #[serde(default = "default_refresh_interval_ms")]
    pub refresh_interval_ms: u64,
    #[serde(default = "default_scan_interval_secs")]
    pub interface_scan_interval_secs: u64,
    #[serde(default = "default_map_max_entries")]
    pub map_max_entries: u32,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: default_refresh_interval_ms(),
            interface_scan_interval_secs: default_scan_interval_secs(),
            map_max_entries: default_map_max_entries(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayConfig {
    #[serde(default)]
    pub show_interface: bool,
    #[serde(default)]
    pub show_packets: bool,
    #[serde(default = "default_sort")]
    pub default_sort: String,
}

fn default_sort() -> String {
    "ip".to_string()
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            show_interface: false,
            show_packets: false,
            default_sort: default_sort(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpRangeEntry {
    pub name: String,
    pub range: String,
}

/// Config after full validation; everything downstream consumes this.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub bridge: String,
    pub refresh_interval_ms: u64,
    pub interface_scan_interval_secs: u64,
    pub map_max_entries: u32,
    pub show_interface: bool,
    pub show_packets: bool,
    pub default_sort: SortMode,
    pub ranges: Vec<IpRange>,
}

pub fn load(path: &Path) -> Result<ValidatedConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    let config: Config =
        toml::from_str(&text).map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;

    let bridge = config.network.bridge.trim().to_string();
    if bridge.is_empty() {
        return Err("network.bridge must not be empty".to_string());
    }
    if config.collector.refresh_interval_ms == 0 {
        return Err("collector.refresh_interval_ms must be > 0".to_string());
    }
    if config.collector.interface_scan_interval_secs == 0 {
        return Err("collector.interface_scan_interval_secs must be > 0".to_string());
    }
    if config.collector.map_max_entries == 0 {
        return Err("collector.map_max_entries must be > 0".to_string());
    }
    let default_sort = match config.display.default_sort.as_str() {
        "ip" => SortMode::Ip,
        "rx" => SortMode::Rx,
        "tx" => SortMode::Tx,
        "total" => SortMode::Total,
        other => {
            return Err(format!(
                "display.default_sort must be one of ip, rx, tx, total; got {other:?}"
            ))
        }
    };
    let ranges = validate_ranges(&config.ip_ranges)?;

    Ok(ValidatedConfig {
        bridge,
        refresh_interval_ms: config.collector.refresh_interval_ms,
        interface_scan_interval_secs: config.collector.interface_scan_interval_secs,
        map_max_entries: config.collector.map_max_entries,
        show_interface: config.display.show_interface,
        show_packets: config.display.show_packets,
        default_sort,
        ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[network]
bridge = "br0"

[collector]
refresh_interval_ms = 1000
interface_scan_interval_secs = 5
map_max_entries = 8192

[display]
show_interface = false
show_packets = false
default_sort = "ip"

[[ip_ranges]]
name = "Range-A"
range = "10.30.8.1-10.30.8.16"

[[ip_ranges]]
name = "Range-B"
range = "10.30.9.1-10.30.9.16"
"#;

    fn load_str(text: &str) -> Result<ValidatedConfig, String> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "vmbw-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, text).unwrap();
        let result = load(&path);
        let _ = std::fs::remove_file(&path);
        result
    }

    #[test]
    fn example_config_loads() {
        let cfg = load_str(EXAMPLE).unwrap();
        assert_eq!(cfg.bridge, "br0");
        assert_eq!(cfg.ranges.len(), 2);
        assert_eq!(cfg.ranges[0].name, "Range-A");
        assert_eq!(cfg.ranges[1].name, "Range-B");
        assert_eq!(cfg.map_max_entries, 8192);
        assert_eq!(cfg.default_sort, SortMode::Ip);
    }

    #[test]
    fn defaults_apply() {
        let text = r#"
[network]
bridge = "br0"

[[ip_ranges]]
name = "A"
range = "10.0.0.1-10.0.0.2"
"#;
        let cfg = load_str(text).unwrap();
        assert_eq!(cfg.refresh_interval_ms, 1000);
        assert_eq!(cfg.interface_scan_interval_secs, 5);
        assert_eq!(cfg.map_max_entries, 8192);
        assert!(!cfg.show_interface);
        assert!(!cfg.show_packets);
    }

    #[test]
    fn rejects_bad_sort() {
        let text = EXAMPLE.replace("default_sort = \"ip\"", "default_sort = \"bogus\"");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("default_sort"), "{err}");
    }

    #[test]
    fn rejects_missing_ranges() {
        let text = "[network]\nbridge = \"br0\"\n";
        let err = load_str(text).unwrap_err();
        assert!(err.contains("[[ip_ranges]]"), "{err}");
    }

    #[test]
    fn rejects_zero_intervals() {
        let text = EXAMPLE.replace("refresh_interval_ms = 1000", "refresh_interval_ms = 0");
        assert!(load_str(&text).is_err());
    }
}
