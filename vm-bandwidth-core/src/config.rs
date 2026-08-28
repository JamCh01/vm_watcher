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
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub experimental: ExperimentalConfig,
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

fn default_swl_map_max_entries() -> u32 {
    256
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
    /// Capacity of the sliding-window-log map ONLY. Each entry reserves one 1024-slot
    /// ring (~16.4 KiB), preallocated by the kernel at load — keep this at the number
    /// of flows you actually intend to limit with `sliding_window_log`, not at the
    /// general map size. Default 256 ≈ 4 MiB; `map_max_entries` (8192) would reserve
    /// ~134 MiB for a feature that is off by default.
    #[serde(default = "default_swl_map_max_entries")]
    pub swl_map_max_entries: u32,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: default_refresh_interval_ms(),
            interface_scan_interval_secs: default_scan_interval_secs(),
            map_max_entries: default_map_max_entries(),
            swl_map_max_entries: default_swl_map_max_entries(),
        }
    }
}

/// Capability switches for features that are expensive or experimental. Sliding
/// Window Log is deliberately NOT a normal algorithm choice: every packet scans a
/// 1024-entry ring under a spin lock, and the ring under-counts (gets lenient) above
/// roughly `1024 / limit_window` packets per second.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalConfig {
    /// Allow `algorithm = "sliding_window_log"` in policies. Off by default.
    #[serde(default)]
    pub enable_sliding_window_log: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Master switch. When disabled the daemon exports nothing and the `--ui` trend
    /// screen explains that metrics are off.
    #[serde(default)]
    pub enabled: bool,
    /// VictoriaMetrics base URL, e.g. `http://127.0.0.1:8428` (localhost) or
    /// `https://vm.example.com:8428` (remote). The daemon posts to
    /// `{url}/api/v1/import/prometheus`; the `--ui` trend screen queries
    /// `{url}/api/v1/query_range`. Remote URLs must use HTTPS; plain HTTP is only
    /// accepted for loopback hosts unless `allow_insecure_http` is set.
    #[serde(default = "default_metrics_url")]
    pub url: String,
    /// Explicit opt-in for remote plain-HTTP metrics URLs (per-customer bandwidth
    /// figures would cross the network unencrypted and unauthenticated). Off by
    /// default; localhost HTTP never needs it.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// How often cumulative per-IP counters are pushed, in seconds.
    #[serde(default = "default_push_interval_secs")]
    pub push_interval_secs: u64,
}

fn default_metrics_url() -> String {
    "http://127.0.0.1:8428".to_string()
}

fn default_push_interval_secs() -> u64 {
    60
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_metrics_url(),
            allow_insecure_http: false,
            push_interval_secs: default_push_interval_secs(),
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
    /// Policing algorithm: `token_bucket`, `leaky_bucket`, `fixed_window`,
    /// `sliding_window_counter`, `sliding_window_log` or `gcra` (default).
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Window length for the window-based algorithms (`1s`–`60s`).
    #[serde(default)]
    pub limit_window: Option<String>,
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
            && self.algorithm.is_none()
            && self.limit_window.is_none()
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
            algorithm: self
                .algorithm
                .map(|s| parse_algorithm(&s).map_err(|e| format!("{what}: {e}")))
                .transpose()?,
            limit_window_secs: dur(self.limit_window, "limit_window")?,
        })
    }
}

/// Map a config string to one of the `ALGO_*` constants.
fn parse_algorithm(s: &str) -> Result<u32, String> {
    use vm_bandwidth_common::*;
    Ok(match s {
        "token_bucket" => ALGO_TOKEN_BUCKET,
        "leaky_bucket" => ALGO_LEAKY_BUCKET,
        "fixed_window" => ALGO_FIXED_WINDOW,
        "sliding_window_counter" => ALGO_SLIDING_WINDOW_COUNTER,
        "sliding_window_log" => ALGO_SLIDING_WINDOW_LOG,
        "gcra" => ALGO_GCRA,
        other => {
            return Err(format!(
                "unknown algorithm '{other}' (expected token_bucket, leaky_bucket, \
                 fixed_window, sliding_window_counter, sliding_window_log or gcra)"
            ))
        }
    })
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
/// The window algorithms compute in MiB and are bounded to a 60s window so their
/// weighted estimates also stay inside `u64`.
const MIN_RATE_BPS: u64 = 100_000; // 100 Kbps
const MAX_RATE_BPS: u64 = 1_000_000_000_000; // 1 Tbps
const MAX_BURST_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
const MIN_LIMIT_WINDOW_SECS: u64 = 1;
const MAX_LIMIT_WINDOW_SECS: u64 = 60;
/// Sanity cap on the SWL map: 65536 rings ≈ 1 GiB of kernel memory. The value exists
/// to catch unit typos (e.g. 256000); any real deployment needs far fewer SWL flows.
const MAX_SWL_MAP_ENTRIES: u32 = 65536;

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
    if let Some(w) = fields.limit_window_secs {
        if !(MIN_LIMIT_WINDOW_SECS..=MAX_LIMIT_WINDOW_SECS).contains(&w) {
            return Err(format!("{what}: limit_window must be between 1s and 60s"));
        }
    }
    Ok(())
}

/// URL policy for the metrics endpoint, enforced with a real URL parser (no string
/// prefix guessing): https anywhere; http only for loopback hosts unless the operator
/// explicitly accepts insecure remote transport.
fn validate_metrics_url(raw: &str, allow_insecure_http: bool) -> Result<(), String> {
    use url::Host;
    let url = url::Url::parse(raw).map_err(|e| format!("metrics.url is not a valid URL: {e}"))?;
    if url.host().is_none() {
        return Err("metrics.url must include a host".to_string());
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match url.host() {
                Some(Host::Domain("localhost")) => true,
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
            if loopback || allow_insecure_http {
                Ok(())
            } else {
                Err(format!(
                    "metrics.url {raw:?}: remote plain HTTP would send customer bandwidth                      figures unencrypted; use https:// or set allow_insecure_http = true                      to accept the risk"
                ))
            }
        }
        other => Err(format!(
            "metrics.url scheme must be http:// or https://; got {other:?}"
        )),
    }
}

/// Sliding Window Log is gated behind `[experimental] enable_sliding_window_log`:
/// refuse configs that select it without the explicit switch.
fn check_swl_enabled(
    eff: &policy::EffectivePolicy,
    enabled: bool,
    what: &str,
) -> Result<(), String> {
    let uses_swl = |d: &Option<policy::DirPolicy>| {
        d.map(|p| p.algorithm == vm_bandwidth_common::ALGO_SLIDING_WINDOW_LOG)
            .unwrap_or(false)
    };
    if (uses_swl(&eff.rx) || uses_swl(&eff.tx)) && !enabled {
        return Err(format!(
            "policy for {what}: algorithm = \"sliding_window_log\" requires \
             [experimental] enable_sliding_window_log = true — every packet scans a \
             1024-entry ring under a spin lock and the log gets lenient above roughly \
             1024/limit_window packets per second; it is not a general-purpose choice"
        ));
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
    pub swl_map_max_entries: u32,
    pub show_interface: bool,
    pub show_packets: bool,
    pub default_sort: SortMode,
    /// VictoriaMetrics export (validated `[metrics]` section).
    pub metrics_enabled: bool,
    pub metrics_url: String,
    pub metrics_push_interval_secs: u64,
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
    // The rate limiter's rolling windows are calibrated in WHOLE tick seconds, so the
    // interval must be second-aligned (a 1500 ms interval used to silently truncate to
    // 1 s ticks and mis-measure bandwidth by 1.5x).
    if config.collector.refresh_interval_ms < 1000
        || !config.collector.refresh_interval_ms.is_multiple_of(1000)
    {
        return Err(
            "collector.refresh_interval_ms must be a whole number of seconds (>= 1000)".to_string(),
        );
    }
    if config.collector.interface_scan_interval_secs == 0 {
        return Err("collector.interface_scan_interval_secs must be > 0".to_string());
    }
    if config.collector.map_max_entries == 0 {
        return Err("collector.map_max_entries must be > 0".to_string());
    }
    if config.collector.swl_map_max_entries == 0 {
        return Err("collector.swl_map_max_entries must be > 0".to_string());
    }
    if config.collector.swl_map_max_entries > MAX_SWL_MAP_ENTRIES {
        return Err(format!(
            "collector.swl_map_max_entries must be at most {MAX_SWL_MAP_ENTRIES}              (each entry preallocates ~16.4 KiB of kernel memory)"
        ));
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

    // Metrics section: validate the URL against what the client can actually do.
    let metrics = &config.metrics;
    if metrics.enabled {
        validate_metrics_url(&metrics.url, metrics.allow_insecure_http)?;
        if !(5..=3600).contains(&metrics.push_interval_secs) {
            return Err(format!(
                "metrics.push_interval_secs must be within 5..=3600; got {}",
                metrics.push_interval_secs
            ));
        }
    }

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
        let eff = policy::resolve(&policy, None, &scope)?;
        check_swl_enabled(&eff, config.experimental.enable_sliding_window_log, &scope)?;

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
            let ov_scope = format!("{} ip {}", scope, ov.ip);
            let eff = policy::resolve(&policy, Some(&fields), &ov_scope)?;
            check_swl_enabled(
                &eff,
                config.experimental.enable_sliding_window_log,
                &ov_scope,
            )?;
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
        swl_map_max_entries: config.collector.swl_map_max_entries,
        show_interface: config.display.show_interface,
        show_packets: config.display.show_packets,
        default_sort,
        metrics_enabled: metrics.enabled,
        metrics_url: metrics.url.trim_end_matches('/').to_string(),
        metrics_push_interval_secs: metrics.push_interval_secs,
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
    fn metrics_defaults_and_validation() {
        let cfg = load_str(EXAMPLE).unwrap();
        assert!(!cfg.metrics_enabled);
        assert_eq!(cfg.metrics_push_interval_secs, 60);

        let text = format!(
            "{EXAMPLE}\n[metrics]\nenabled = true\nurl = \"http://127.0.0.1:8428/\"\npush_interval_secs = 30\n"
        );
        let cfg = load_str(&text).unwrap();
        assert!(cfg.metrics_enabled);
        // trailing slash normalised
        assert_eq!(cfg.metrics_url, "http://127.0.0.1:8428");
        assert_eq!(cfg.metrics_push_interval_secs, 30);

        // https is fine; unknown schemes are not.
        let text = format!(
            "{EXAMPLE}
[metrics]
enabled = true
url = \"https://vm:8428\"
"
        );
        assert!(load_str(&text).is_ok());
        let text = format!(
            "{EXAMPLE}
[metrics]
enabled = true
url = \"ftp://vm:8428\"
"
        );
        assert!(load_str(&text).unwrap_err().contains("scheme"));

        let text = format!(
            "{EXAMPLE}
[metrics]
enabled = true
url = \"http://127.0.0.1:8428\"
push_interval_secs = 1
"
        );
        assert!(load_str(&text).unwrap_err().contains("push_interval_secs"));

        // disabled section skips all validation
        let text = format!(
            "{EXAMPLE}
[metrics]
enabled = false
url = \"nonsense\"
"
        );
        assert!(load_str(&text).is_ok());
    }

    #[test]
    fn metrics_url_policy() {
        fn url_cfg(url: &str, extra: &str) -> String {
            format!(
                "{EXAMPLE}
[metrics]
enabled = true
url = \"{url}\"
{extra}"
            )
        }
        // Loopback HTTP: always fine.
        assert!(load_str(&url_cfg("http://127.0.0.1:8428", "")).is_ok());
        assert!(load_str(&url_cfg("http://localhost:8428", "")).is_ok());
        assert!(load_str(&url_cfg("http://[::1]:8428", "")).is_ok());
        // Remote HTTP: refused unless explicitly accepted.
        let err = load_str(&url_cfg("http://10.1.2.3:8428", "")).unwrap_err();
        assert!(err.contains("allow_insecure_http"), "{err}");
        assert!(load_str(&url_cfg(
            "http://10.1.2.3:8428",
            "allow_insecure_http = true
"
        ))
        .is_ok());
        // Remote HTTPS: fine without any flag.
        assert!(load_str(&url_cfg("https://vm.example.com:8428", "")).is_ok());
        // Garbage: parser error, host required.
        assert!(load_str(&url_cfg("not a url", "")).is_err());
        assert!(load_str(&url_cfg("http://", "")).is_err());
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

    #[test]
    fn rejects_non_second_aligned_interval() {
        let text = EXAMPLE.replace("refresh_interval_ms = 1000", "refresh_interval_ms = 1500");
        assert!(load_str(&text).is_err());
    }

    #[test]
    fn accepts_huge_ranges() {
        // The whitelist is an LPM trie of CIDR prefixes: range size no longer costs
        // one map entry per address, so large ranges are valid.
        let text =
            "[network]\nbridge = \"br0\"\n\n[[ip_ranges]]\nname = \"huge\"\nrange = \"192.0.0.0-195.255.255.255\"\n";
        assert!(load_str(text).is_ok());
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

    const SWL_POLICY: &str = r#"
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
  algorithm = "sliding_window_log"
  limit_window = "10s"
"#;

    #[test]
    fn swl_requires_explicit_experimental_switch() {
        let err = load_str(SWL_POLICY).unwrap_err();
        assert!(err.contains("enable_sliding_window_log"), "{err}");

        let text = format!(
            "{SWL_POLICY}
[experimental]
enable_sliding_window_log = true
"
        );
        assert!(load_str(&text).is_ok());
    }

    #[test]
    fn swl_switch_required_for_overrides_too() {
        // Range default is plain GCRA; a single override switches to SWL — the gate
        // must fire for the merged override policy too.
        let base = r#"
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
  algorithm = "sliding_window_log"
  limit_window = "10s"
"#;
        let err = load_str(base).unwrap_err();
        assert!(err.contains("enable_sliding_window_log"), "{err}");

        let text = format!("{base}\n[experimental]\nenable_sliding_window_log = true\n");
        assert!(load_str(&text).is_ok());
    }

    #[test]
    fn swl_map_capacity_validated() {
        let cfg = load_str(EXAMPLE).unwrap();
        assert_eq!(cfg.swl_map_max_entries, 256); // conservative default

        let text = EXAMPLE.replace(
            "map_max_entries = 8192",
            "map_max_entries = 8192
swl_map_max_entries = 64",
        );
        assert_eq!(load_str(&text).unwrap().swl_map_max_entries, 64);

        let text = EXAMPLE.replace(
            "map_max_entries = 8192",
            "map_max_entries = 8192
swl_map_max_entries = 0",
        );
        assert!(load_str(&text).is_err());

        let text = EXAMPLE.replace(
            "map_max_entries = 8192",
            "map_max_entries = 8192
swl_map_max_entries = 999999",
        );
        let err = load_str(&text).unwrap_err();
        assert!(err.contains("16.4 KiB"), "{err}");
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
