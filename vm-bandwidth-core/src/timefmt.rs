//! Minimal UTC timestamp formatting (no chrono dependency).

/// Format a UNIX timestamp (seconds) as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_unix_utc(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Current wall-clock time as UNIX seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn known_timestamps() {
        // 2026-08-26 09:00:00 UTC
        assert_eq!(format_unix_utc(1_787_734_800), "2026-08-26 09:00:00 UTC");
        // 2000-02-29 12:34:56 UTC (leap day)
        assert_eq!(format_unix_utc(951_827_696), "2000-02-29 12:34:56 UTC");
    }

    #[test]
    fn now_is_reasonable() {
        assert!(now_unix() > 1_700_000_000);
    }
}
