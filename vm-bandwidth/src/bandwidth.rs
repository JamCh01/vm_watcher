//! Human-readable formatting for rates and totals.
//!
//! Rates: bit/s, Kbit/s, Mbit/s, Gbit/s (1000-based, matching the spec examples
//! "820 Mbps", "1.2 Gbps"). Totals: B, KiB, MiB, GiB, TiB (1024-based).

fn fmt_scaled(value: f64, units: &[&str], base: f64) -> String {
    let mut value = value;
    let mut unit = 0;
    while value >= base && unit + 1 < units.len() {
        value /= base;
        unit += 1;
    }
    // integral values print as integers ("96 GiB", "820 Mbit/s"),
    // fractional ones with one decimal ("8.2 TiB", "1.2 Gbit/s")
    let number = if unit == 0 || (value - value.round()).abs() < 0.05 {
        format!("{:.0}", value)
    } else {
        format!("{:.1}", value)
    };
    if units[unit].is_empty() {
        number
    } else {
        format!("{number} {}", units[unit])
    }
}

pub fn format_bps(bps: f64) -> String {
    const UNITS: [&str; 4] = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"];
    if bps <= 0.0 {
        return "0 bit/s".to_string();
    }
    fmt_scaled(bps, &UNITS, 1000.0)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    fmt_scaled(bytes as f64, &UNITS, 1024.0)
}

pub fn format_count(count: u64) -> String {
    const UNITS: [&str; 4] = ["", "K", "M", "G"];
    fmt_scaled(count as f64, &UNITS, 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_units() {
        assert_eq!(format_bps(0.0), "0 bit/s");
        assert_eq!(format_bps(999.0), "999 bit/s");
        assert_eq!(format_bps(1_000.0), "1 Kbit/s");
        assert_eq!(format_bps(15_000.0), "15 Kbit/s");
        assert_eq!(format_bps(820e6), "820 Mbit/s");
        assert_eq!(format_bps(120e6), "120 Mbit/s");
        assert_eq!(format_bps(1.2e9), "1.2 Gbit/s");
        assert_eq!(format_bps(12.34e9), "12.3 Gbit/s");
        // negative deltas must never happen, but formatting must not go weird if they do
        assert_eq!(format_bps(-5.0), "0 bit/s");
    }

    #[test]
    fn byte_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1 KiB");
        assert_eq!(format_bytes(310 * 1024 * 1024 * 1024), "310 GiB");
        assert_eq!(format_bytes(96 * 1024 * 1024 * 1024), "96 GiB");
        let tib = format_bytes((8.2 * 1024.0f64.powi(4)) as u64);
        assert_eq!(tib, "8.2 TiB");
        let big = format_bytes((16.3 * 1024.0f64.powi(4)) as u64);
        assert_eq!(big, "16.3 TiB");
    }

    #[test]
    fn count_units() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(1500), "1.5 K");
        assert_eq!(format_count(2000), "2 K");
        assert_eq!(format_count(2_500_000), "2.5 M");
    }
}
