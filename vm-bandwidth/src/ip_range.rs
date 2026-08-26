//! `开始IP-结束IP` range parsing, validation and overlap checking.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::config::IpRangeEntry;

/// One configured, validated IP range. `start <= end` always holds.
#[derive(Debug, Clone)]
pub struct IpRange {
    pub name: String,
    pub start: u32,
    pub end: u32,
}

impl IpRange {
    pub fn len(&self) -> u64 {
        u64::from(self.end - self.start) + 1
    }

    /// `10.30.8.1-10.30.8.16`
    pub fn display(&self) -> String {
        format!(
            "{}-{}",
            Ipv4Addr::from(self.start),
            Ipv4Addr::from(self.end)
        )
    }
}

fn parse_ip(what: &str, raw: &str) -> Result<u32, String> {
    raw.trim()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| format!("range {raw:?}: {what} is not a valid IPv4 address"))
}

/// Parse `start-end`. Rejects CIDR, wildcards, trailing dashes and reversed ranges.
pub fn parse_range(raw: &str) -> Result<(u32, u32), String> {
    let (start_str, end_str) = raw.split_once('-').ok_or_else(|| {
        format!("range {raw:?}: must use the START-END format, e.g. 10.30.8.1-10.30.8.16")
    })?;
    if end_str.contains('-') {
        return Err(format!("range {raw:?}: more than one '-'"));
    }
    let start = parse_ip("start address", start_str)
        .map_err(|_| format!("range {raw:?}: {start_str:?} is not a valid IPv4 address"))?;
    let end = parse_ip("end address", end_str)
        .map_err(|_| format!("range {raw:?}: {end_str:?} is not a valid IPv4 address"))?;
    if start > end {
        return Err(format!(
            "range {raw:?}: start is greater than end (reversed ranges are not supported)"
        ));
    }
    Ok((start, end))
}

/// Validate all `[[ip_ranges]]` entries. Every error names the offending range.
pub fn validate_ranges(entries: &[IpRangeEntry]) -> Result<Vec<IpRange>, String> {
    if entries.is_empty() {
        return Err("config must contain at least one [[ip_ranges]] entry".to_string());
    }

    let mut ranges = Vec::with_capacity(entries.len());
    let mut names: HashSet<&str> = HashSet::new();
    for entry in entries {
        if entry.name.trim().is_empty() {
            return Err(format!(
                "ip range {:?}: name must not be empty",
                entry.range
            ));
        }
        if !names.insert(entry.name.as_str()) {
            return Err(format!(
                "ip range name {:?} is used more than once",
                entry.name
            ));
        }
        let (start, end) = parse_range(&entry.range)?;
        ranges.push(IpRange {
            name: entry.name.clone(),
            start,
            end,
        });
    }

    // Ranges are disjoint iff, sorted by start, no range begins before the previous one ends.
    let mut order: Vec<usize> = (0..ranges.len()).collect();
    order.sort_by_key(|&i| ranges[i].start);
    for pair in order.windows(2) {
        let a = &ranges[pair[0]];
        let b = &ranges[pair[1]];
        if b.start <= a.end {
            return Err(format!(
                "IP range overlap:\n{}: {}\n{}: {}",
                a.name,
                a.display(),
                b.name,
                b.display()
            ));
        }
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, range: &str) -> IpRangeEntry {
        IpRangeEntry {
            name: name.to_string(),
            range: range.to_string(),
        }
    }

    #[test]
    fn parse_valid() {
        let (start, end) = parse_range("10.30.8.1-10.30.8.16").unwrap();
        assert_eq!(start, u32::from(Ipv4Addr::new(10, 30, 8, 1)));
        assert_eq!(end, u32::from(Ipv4Addr::new(10, 30, 8, 16)));
    }

    #[test]
    fn parse_single_ip_range() {
        let (start, end) = parse_range("10.0.0.5-10.0.0.5").unwrap();
        assert_eq!(start, end);
    }

    #[test]
    fn reject_bad_formats() {
        for bad in [
            "10.30.8.0/24",          // CIDR not supported
            "10.30.8.*",             // wildcard not supported
            "10.30.8.1-",            // missing end
            "-10.30.8.1",            // missing start
            "10.30.8.100-10.30.8.1", // reversed
            "10.30.8",               // not a full IPv4
            "10.30.8.1-10.30.8.2-10.30.8.3",
            "banana",
        ] {
            assert!(parse_range(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn validate_requires_entries() {
        assert!(validate_ranges(&[]).is_err());
    }

    #[test]
    fn validate_rejects_empty_name() {
        let err = validate_ranges(&[entry("", "10.0.0.1-10.0.0.2")]).unwrap_err();
        assert!(err.contains("name must not be empty"), "{err}");
    }

    #[test]
    fn validate_rejects_duplicate_names() {
        let err = validate_ranges(&[
            entry("A", "10.0.0.1-10.0.0.2"),
            entry("A", "10.0.1.1-10.0.1.2"),
        ])
        .unwrap_err();
        assert!(err.contains("\"A\""), "{err}");
    }

    #[test]
    fn validate_detects_overlap() {
        let err = validate_ranges(&[
            entry("A", "10.30.8.1-10.30.8.16"),
            entry("B", "10.30.8.10-10.30.8.30"),
        ])
        .unwrap_err();
        assert!(err.contains("IP range overlap"), "{err}");
        assert!(err.contains("A: 10.30.8.1-10.30.8.16"), "{err}");
        assert!(err.contains("B: 10.30.8.10-10.30.8.30"), "{err}");
    }

    #[test]
    fn adjacent_ranges_are_not_overlap() {
        let ok = validate_ranges(&[
            entry("A", "10.30.8.1-10.30.8.16"),
            entry("B", "10.30.8.17-10.30.8.30"),
        ]);
        assert!(ok.is_ok());
    }

    #[test]
    fn contains_and_len() {
        let r = validate_ranges(&[entry("A", "10.30.8.1-10.30.8.16")])
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(r.len(), 16);
        assert_eq!(r.display(), "10.30.8.1-10.30.8.16");
    }
}
