//! Load and validate `config.toml`. The program refuses to start (or reload) on any
//! validation error, always naming the offending value.

use std::collections::HashMap;
use std::ops::Deref;
use std::path::Path;

use serde::Deserialize;

use crate::ip_range::{validate_ranges, IpRange};
use crate::policy::{self, PolicyFields};
use crate::units;

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

/// A single limiter parameter set as written in TOML. Every value is a string with a
/// unit (`1Gbps`, `5m`, `80%`, `4MiB`); all fields are optional so an IP override can
/// inherit what it does not repeat.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntry {
    #[serde(default)]
    pub rx_threshold: Option<String>,
    #[serde(default)]
    pub tx_threshold: Option<String>,
    #[serde(default)]
    pub rx_limit: Option<String>,
    #[serde(default)]
    pub tx_limit: Option<String>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub trigger_ratio: Option<String>,
    #[serde(default)]
    pub limit_duration: Option<String>,
    #[serde(default)]
    pub burst: Option<String>,
}

impl PolicyEntry {
    fn is_empty(&self) -> bool {
        self.rx_threshold.is_none()
            && self.tx_threshold.is_none()
            && self.rx_limit.is_none()
            && self.tx_limit.is_none()
            && self.window.is_none()
            && self.trigger_ratio.is_none()
            && self.limit_duration.is_none()
            && self.burst.is_none()
    }

    /// Parse every present unit into exact integers. `what` names the offending scope.
    fn into_fields(self, what: &str) -> Result<PolicyFields, String> {
        let rate = |v: Option<String>, name: &str| -> Result<Option<u64>, String> {
            v.map(|s| units::parse_rate_bps(&s).map_err(|e| format!("{what}: {e} ({name})")))
                .transpose()
        };
        let dur = |v: Option<String>, name: &str| -> Result<Option<u64>, String> {
            v.map(|s| units::parse_duration_secs(&s).map_err(|e| format!("{what}: {e} ({name})")))
                .transpose()
        };
        Ok(PolicyFields {
            rx_threshold_bps: rate(self.rx_threshold, "rx_threshold")?,
            tx_threshold_bps: rate(self.tx_threshold, "tx_threshold")?,
            rx_limit_bps: rate(self.rx_limit, "rx_limit")?,
            tx_limit_bps: rate(self.tx_limit, "tx_limit")?,
            window_secs: dur(self.window, "window")?,
            trigger_ratio_pct: self
                .trigger_ratio
                .map(|s| {
                    units::parse_percent(&s).map_err(|e| format!("{what}: {e} (trigger_ratio)"))
                })
                .transpose()?,
            limit_duration_secs: dur(self.limit_duration, "limit_duration")?,
            burst_bytes: self
                .burst
                .map(|s| units::parse_bytes(&s).map_err(|e| format!("{what}: {e} (burst)")))
                .transpose()?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideEntry {
    pub ip: String,
    #[serde(flatten)]
    pub policy: PolicyEntry,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpRangeEntry {
    pub name: String,
    pub range: String,
    #[serde(default)]
    pub policy: Option<PolicyEntry>,
    #[serde(default)]
    pub overrides: Vec<OverrideEntry>,
}

/// One validated range: its addresses plus the resolved limiter policy inputs.
#[derive(Debug, Clone)]
pub struct ValidatedRange {
    pub inner: IpRange,
    /// Parsed default policy (empty when the range is monitoring-only).
    pub policy: PolicyFields,
    /// Parsed per-IP overrides, keyed by IP. Only IPs inside `inner` are allowed.
    pub overrides: HashMap<u32, PolicyFields>,
}

impl Deref for ValidatedRange {
    type Target = IpRange;
    fn deref(&self) -> &IpRange {
        &self.inner
    }
}

/// Arithmetic-safe bounds for rates and burst.
///
/// The eBPF GCRA data path computes `burst_bytes * 8 * 1e9` in `u64`, so `burst` is
/// capped so that product cannot wrap; rates are bounded to keep every derived number
/// (increment, tolerance, deadline) provably inside `u64` for any packet length.
const MIN_RATE_BPS: u64 = 100_000; // 100 Kbps
const MAX_RATE_BPS: u64 = 1_000_000_000_000; // 1 Tbps
const MAX_BURST_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

fn check_policy_bounds(fields: &PolicyFields, what: &str) -> Result<(), String> {
    for (name, value) in [
        ("rx_threshold", fields.rx_threshold_bps),
        ("tx_threshold", fields.tx_threshold_bps),
        ("rx_limit", fields.rx_limit_bps),
        ("tx_limit", fields.tx_limit_bps),
    ] {
        if let Some(v) = value {
            if !(MIN_RATE_BPS..=MAX_RATE_BPS).contains(&v) {
                return Err(format!("{what}: {name} must be between 100Kbps and 1Tbps"));
            }
        }
    }
    if let Some(b) = fields.burst_bytes {
        if b > MAX_BURST_BYTES {
            return Err(format!("{what}: burst must be at most 1GiB"));
        }
    }
    Ok(())
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
    pub ranges: Vec<ValidatedRange>,
}

impl ValidatedConfig {
    /// Convenience for the collector / whitelist paths that only care about addresses.
    pub fn ip_ranges(&self) -> Vec<IpRange> {
        self.ranges.iter().map(|r| r.inner.clone()).collect()
    }
}

pub fn load(path: &Path) -> Result<ValidatedConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{e} (in {})", path.display()))
}

/// Parse + validate a config document. Split out so tests can drive it without files.
pub fn parse(text: &str) -> Result<ValidatedConfig, String> {
    let config: Config = toml::from_str(text).map_err(|e| format!("invalid TOML: {e}"))?;

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

    // Attach parsed policies, validating units, override placement and completeness.
    let mut validated = Vec::with_capacity(ranges.len());
    for (entry, range) in config.ip_ranges.iter().zip(ranges) {
        let scope = format!("range {}", entry.name);
        let policy = match &entry.policy {
            Some(p) if !p.is_empty() => {
                let fields = p.clone().into_fields(&scope)?;
                check_policy_bounds(&fields, &scope)?;
                fields
            }
            _ => PolicyFields::default(),
        };

        // The range default must itself be internally consistent.
        policy::resolve(&policy, None, &scope)?;

        let mut overrides = HashMap::new();
        for ov in &entry.overrides {
            let ip = ov
                .ip
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .map(u32::from)
                .map_err(|_| format!("{scope}: override ip {:?} is not a valid IPv4", ov.ip))?;
            if ip < range.start || ip > range.end {
                return Err(format!(
                    "{scope}: override ip {} is outside the range {}",
                    std::net::Ipv4Addr::from(ip),
                    range.display()
                ));
            }
            if ov.policy.is_empty() {
                return Err(format!(
                    "{scope}: override for ip {} sets no policy fields",
                    ov.ip
                ));
            }
            let fields = ov
                .policy
                .clone()
                .into_fields(&format!("{scope} override {}", ov.ip))?;
            check_policy_bounds(&fields, &format!("{scope} override {}", ov.ip))?;
            // The merged result must be complete (inheritance fills what is missing).
            policy::resolve(&policy, Some(&fields), &format!("{} ip {}", scope, ov.ip))?;
            if overrides.insert(ip, fields).is_some() {
                return Err(format!("{scope}: duplicate override for ip {}", ov.ip));
            }
        }

        validated.push(ValidatedRange {
            inner: range,
            policy,
            overrides,
        });
    }

    Ok(ValidatedConfig {
        bridge,
        refresh_interval_ms: config.collector.refresh_interval_ms,
        interface_scan_interval_secs: config.collector.interface_scan_interval_secs,
        map_max_entries: config.collector.map_max_entries,
        show_interface: config.display.show_interface,
        show_packets: config.display.show_packets,
        default_sort,
        ranges: validated,
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
        parse(text)
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

    const POLICY_EXAMPLE: &str = r#"
[network]
bridge = "br0"

[[ip_ranges]]
name = "Range-A"
range = "10.30.8.1-10.30.8.16"

  [ip_ranges.policy]
  rx_threshold = "1Gbps"
  tx_threshold = "500Mbps"
  window = "5m"
  trigger_ratio = "80%"
  rx_limit = "500Mbps"
  tx_limit = "200Mbps"
  limit_duration = "30m"
  burst = "4MiB"

  [[ip_ranges.overrides]]
  ip = "10.30.8.3"
  rx_threshold = "2Gbps"
  rx_limit = "800Mbps"
"#;

    #[test]
    fn policy_parses() {
        let cfg = load_str(POLICY_EXAMPLE).unwrap();
        let r = &cfg.ranges[0];
        assert_eq!(r.policy.rx_threshold_bps, Some(1_000_000_000));
        assert_eq!(r.policy.tx_threshold_bps, Some(500_000_000));
        assert_eq!(r.policy.window_secs, Some(300));
        assert_eq!(r.policy.trigger_ratio_pct, Some(80));
        assert_eq!(r.policy.rx_limit_bps, Some(500_000_000));
        assert_eq!(r.policy.tx_limit_bps, Some(200_000_000));
        assert_eq!(r.policy.limit_duration_secs, Some(1800));
        assert_eq!(r.policy.burst_bytes, Some(4 * 1024 * 1024));
        assert_eq!(r.overrides.len(), 1);
        let ov = &r.overrides[&u32::from(std::net::Ipv4Addr::new(10, 30, 8, 3))];
        assert_eq!(ov.rx_threshold_bps, Some(2_000_000_000));
        assert_eq!(ov.rx_limit_bps, Some(800_000_000));
        assert_eq!(ov.window_secs, None); // inherited at resolve time
    }

    #[test]
    fn policy_outside_range_rejected() {
        let text = POLICY_EXAMPLE.replace("10.30.8.3", "10.30.9.99");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("outside the range"), "{err}");
    }

    #[test]
    fn incomplete_range_policy_rejected() {
        let text = r#"
[network]
bridge = "br0"

[[ip_ranges]]
name = "A"
range = "10.0.0.1-10.0.0.2"

  [ip_ranges.policy]
  rx_threshold = "1Gbps"
"#;
        let err = load_str(text).unwrap_err();
        assert!(err.contains("incomplete"), "{err}");
    }

    #[test]
    fn bad_unit_rejected() {
        let text = POLICY_EXAMPLE.replace("1Gbps", "1Xbps");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("unknown unit"), "{err}");
    }

    #[test]
    fn out_of_bounds_rate_rejected() {
        // 2000Gbps = 2e12 bps > MAX_RATE_BPS (1 Tbps).
        let text = POLICY_EXAMPLE.replace("rx_limit = \"500Mbps\"", "rx_limit = \"2000Gbps\"");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("between 100Kbps and 1Tbps"), "{err}");

        // 50Kbps < MIN_RATE_BPS (100 Kbps).
        let text = POLICY_EXAMPLE.replace("rx_threshold = \"1Gbps\"", "rx_threshold = \"50Kbps\"");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("between 100Kbps and 1Tbps"), "{err}");
    }

    #[test]
    fn oversized_burst_rejected() {
        let text = POLICY_EXAMPLE.replace("burst = \"4MiB\"", "burst = \"2GiB\"");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("at most 1GiB"), "{err}");
    }

    #[test]
    fn duplicate_override_rejected() {
        let dup = r#"
  [[ip_ranges.overrides]]
  ip = "10.30.8.3"
  tx_limit = "100Mbps"
  window = "1m"
  trigger_ratio = "50%"
  limit_duration = "5m"
  burst = "1MiB"
  tx_threshold = "200Mbps"
"#;
        let text = format!("{POLICY_EXAMPLE}{dup}");
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("duplicate override"), "{err}");
    }
}
