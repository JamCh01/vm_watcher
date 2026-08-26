//! Parsing of human-friendly config units into exact integers.
//!
//! Config values are always whole numbers with a unit suffix; floats are rejected so no
//! floating point ever leaks toward the eBPF data path. All parsers name the offending
//! value in their error.

/// Parse a bit rate such as `100Mbps`, `500Mbps`, `1Gbps` into bits per second.
///
/// Accepted suffixes (case-insensitive): `bps`/`bit/s`, `Kbps`/`Kbit/s`,
/// `Mbps`/`Mbit/s`, `Gbps`/`Gbit/s`. Multipliers are 1000-based.
pub fn parse_rate_bps(raw: &str) -> Result<u64, String> {
    let (num, unit) = split_unit(raw, "bit rate")?;
    let mult: u64 = match unit.as_str() {
        "bps" | "bit/s" => 1,
        "kbps" | "kbit/s" => 1_000,
        "mbps" | "mbit/s" => 1_000_000,
        "gbps" | "gbit/s" => 1_000_000_000,
        other => {
            return Err(format!(
                "bit rate {raw:?}: unknown unit {other:?} (expected bps, Kbps, Mbps or Gbps)"
            ))
        }
    };
    nonzero(num.checked_mul(mult), raw, "bit rate")
}

/// Parse a duration such as `5m`, `30m`, `90s`, `1h` into whole seconds.
pub fn parse_duration_secs(raw: &str) -> Result<u64, String> {
    let (num, unit) = split_unit(raw, "duration")?;
    let mult: u64 = match unit.as_str() {
        "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hour" | "hours" => 3600,
        other => {
            return Err(format!(
                "duration {raw:?}: unknown unit {other:?} (expected s, m or h)"
            ))
        }
    };
    nonzero(num.checked_mul(mult), raw, "duration")
}

/// Parse a byte size such as `4MiB`, `512KiB`, `1GiB` into bytes.
///
/// Binary units (1024-based) match how totals are displayed elsewhere. Plain `B` and
/// decimal `KB`/`MB`/`GB` (1000-based) are also accepted.
pub fn parse_bytes(raw: &str) -> Result<u64, String> {
    let (num, unit) = split_unit(raw, "byte size")?;
    let mult: u64 = match unit.as_str() {
        "b" => 1,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        other => {
            return Err(format!(
            "byte size {raw:?}: unknown unit {other:?} (expected B, KB, MB, GB, KiB, MiB or GiB)"
        ))
        }
    };
    nonzero(num.checked_mul(mult), raw, "byte size")
}

/// Parse a percentage such as `80%` into an integer in `1..=100`.
///
/// `0%` is rejected: a zero trigger ratio would fire immediately and a value above 100%
/// can never trigger.
pub fn parse_percent(raw: &str) -> Result<u8, String> {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_suffix('%')
        .ok_or_else(|| format!("percentage {raw:?}: must end with '%'"))?;
    let value: u8 = body
        .trim()
        .parse()
        .map_err(|_| format!("percentage {raw:?}: not a whole number"))?;
    if !(1..=100).contains(&value) {
        return Err(format!("percentage {raw:?}: must be between 1% and 100%"));
    }
    Ok(value)
}

/// Turn an optional product into a required, non-zero value with a clear error.
fn nonzero(value: Option<u64>, raw: &str, what: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("{what} {raw:?}: overflow"))?;
    if value == 0 {
        return Err(format!("{what} {raw:?}: must be > 0"));
    }
    Ok(value)
}

/// Split `raw` into a whole-number part and a lower-cased unit suffix.
fn split_unit(raw: &str, what: &str) -> Result<(u64, String), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{what} {raw:?}: empty value"));
    }
    let boundary = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    if boundary == 0 {
        return Err(format!("{what} {raw:?}: missing numeric value"));
    }
    let num: u64 = trimmed[..boundary]
        .parse()
        .map_err(|_| format!("{what} {raw:?}: not a whole number"))?;
    let unit = trimmed[boundary..].trim().to_ascii_lowercase();
    if unit.is_empty() {
        return Err(format!("{what} {raw:?}: missing unit"));
    }
    Ok((num, unit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates() {
        assert_eq!(parse_rate_bps("100Mbps").unwrap(), 100_000_000);
        assert_eq!(parse_rate_bps("500Mbps").unwrap(), 500_000_000);
        assert_eq!(parse_rate_bps("1Gbps").unwrap(), 1_000_000_000);
        assert_eq!(parse_rate_bps("2Gbps").unwrap(), 2_000_000_000);
        assert_eq!(parse_rate_bps("800Mbps").unwrap(), 800_000_000);
        assert_eq!(parse_rate_bps("1gbps").unwrap(), 1_000_000_000);
        assert_eq!(parse_rate_bps("512Kbps").unwrap(), 512_000);
        assert_eq!(parse_rate_bps("100Mbit/s").unwrap(), 100_000_000);
        assert_eq!(parse_rate_bps("  1Gbps  ").unwrap(), 1_000_000_000);
    }

    #[test]
    fn rate_rejects() {
        for bad in [
            "", "Mbps", "1.5Gbps", "0Mbps", "-1Mbps", "1Tbps", "1 Gbps x", "Gbps1",
        ] {
            assert!(parse_rate_bps(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("30m").unwrap(), 1800);
        assert_eq!(parse_duration_secs("90s").unwrap(), 90);
        assert_eq!(parse_duration_secs("1h").unwrap(), 3600);
        assert_eq!(parse_duration_secs("2m").unwrap(), 120);
        assert_eq!(parse_duration_secs("10m").unwrap(), 600);
    }

    #[test]
    fn duration_rejects() {
        for bad in ["", "5", "m", "0m", "5x", "-5m", "1.5m"] {
            assert!(parse_duration_secs(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("4MiB").unwrap(), 4 * 1024 * 1024);
        assert_eq!(parse_bytes("1MiB").unwrap(), 1024 * 1024);
        assert_eq!(parse_bytes("512KiB").unwrap(), 512 * 1024);
        assert_eq!(parse_bytes("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("1500B").unwrap(), 1500);
        assert_eq!(parse_bytes("1MB").unwrap(), 1_000_000);
    }

    #[test]
    fn bytes_rejects() {
        for bad in ["", "MiB", "0MiB", "4 TiB", "4XiB", "-1KiB"] {
            assert!(parse_bytes(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn percent() {
        assert_eq!(parse_percent("80%").unwrap(), 80);
        assert_eq!(parse_percent("1%").unwrap(), 1);
        assert_eq!(parse_percent("100%").unwrap(), 100);
        assert_eq!(parse_percent(" 50% ").unwrap(), 50);
    }

    #[test]
    fn percent_rejects() {
        for bad in ["", "80", "0%", "101%", "-5%", "80.5%", "%"] {
            assert!(parse_percent(bad).is_err(), "accepted {bad:?}");
        }
    }
}
