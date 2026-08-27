//! `开始IP-结束IP` range parsing, validation and overlap checking.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::config::IpRangeEntry;

/// One CIDR prefix: `network` with its top `prefix_len` bits fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub prefix_len: u8,
    pub network: u32,
}

impl Cidr {
    /// `10.30.8.0/24`
    pub fn display(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix_len)
    }

    /// Inclusive address span covered by this prefix.
    pub fn span(&self) -> (u32, u32) {
        let size = if self.prefix_len == 0 {
            1u64 << 32
        } else {
            1u64 << (32 - self.prefix_len)
        };
        let start = u64::from(self.network);
        (start as u32, (start + size - 1) as u32)
    }
}

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

    /// A valid range always contains at least one address; required by clippy.
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn contains(&self, ip: u32) -> bool {
        (self.start..=self.end).contains(&ip)
    }

    /// Minimal set of CIDR prefixes whose union is exactly `start..=end`. This is what
    /// gets loaded into the LPM-trie whitelist, so a range costs O(log) map entries
    /// instead of one entry per address. At most 62 prefixes per range.
    pub fn cidrs(&self) -> Vec<Cidr> {
        let mut out = Vec::new();
        let mut cur = u64::from(self.start);
        let end = u64::from(self.end);
        while cur <= end {
            // Largest power-of-two block starting at `cur` that stays inside the range:
            // alignment limits the block size (a 2^k block needs a 2^k-aligned start),
            // the remaining length bounds it. A u64 cursor keeps `end = u32::MAX` safe.
            let align_bits = if cur == 0 { 32 } else { cur.trailing_zeros() };
            let mut bits = 0u32;
            while bits < align_bits && bits < 32 {
                let next = bits + 1;
                if cur + (1u64 << next) - 1 > end {
                    break;
                }
                bits = next;
            }
            out.push(Cidr {
                prefix_len: (32 - bits) as u8,
                network: cur as u32,
            });
            cur += 1u64 << bits;
        }
        out
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
            policy: None,
            overrides: Vec::new(),
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
        assert!(r.contains(u32::from(Ipv4Addr::new(10, 30, 8, 1))));
        assert!(!r.contains(u32::from(Ipv4Addr::new(10, 30, 8, 17))));
    }

    fn one_range(range: &str) -> IpRange {
        validate_ranges(&[entry("A", range)])
            .unwrap()
            .pop()
            .unwrap()
    }

    #[test]
    fn cidr_single_ip() {
        assert_eq!(
            one_range("10.0.0.5-10.0.0.5").cidrs(),
            vec![Cidr {
                prefix_len: 32,
                network: u32::from(Ipv4Addr::new(10, 0, 0, 5))
            }]
        );
    }

    #[test]
    fn cidr_aligned_block() {
        assert_eq!(
            one_range("10.30.8.0-10.30.8.255").cidrs(),
            vec![Cidr {
                prefix_len: 24,
                network: u32::from(Ipv4Addr::new(10, 30, 8, 0))
            }]
        );
    }

    #[test]
    fn cidr_full_space() {
        assert_eq!(
            one_range("0.0.0.0-255.255.255.255").cidrs(),
            vec![Cidr {
                prefix_len: 0,
                network: 0
            }]
        );
    }

    #[test]
    fn cidr_irregular_known_answer() {
        // 121-130: /32 + /31 + /30 + /31 + /32.
        let base = u32::from(Ipv4Addr::new(10, 30, 10, 0));
        assert_eq!(
            one_range("10.30.10.121-10.30.10.130").cidrs(),
            vec![
                Cidr {
                    prefix_len: 32,
                    network: base | 121
                },
                Cidr {
                    prefix_len: 31,
                    network: base | 122
                },
                Cidr {
                    prefix_len: 30,
                    network: base | 124
                },
                Cidr {
                    prefix_len: 31,
                    network: base | 128
                },
                Cidr {
                    prefix_len: 32,
                    network: base | 130
                },
            ]
        );
    }

    #[test]
    fn cidrs_reassemble_exactly() {
        // The decomposed prefixes must tile the original range: contiguous, no gaps.
        for range in [
            "10.30.10.121-10.30.10.130",
            "192.168.1.3-192.168.7.250",
            "10.0.0.0-10.0.0.255",
            "1.2.3.4-5.6.7.8",
        ] {
            let r = one_range(range);
            let list = r.cidrs();
            let (first_start, _) = list.first().unwrap().span();
            let (_, last_end) = list.last().unwrap().span();
            assert_eq!(first_start, r.start, "{range}: bad first prefix");
            assert_eq!(last_end, r.end, "{range}: bad last prefix");
            for pair in list.windows(2) {
                let (_, prev_end) = pair[0].span();
                let (next_start, _) = pair[1].span();
                assert_eq!(next_start, prev_end + 1, "{range}: gap or overlap");
            }
            let total: u64 = list
                .iter()
                .map(|c| {
                    let (s, e) = c.span();
                    u64::from(e - s) + 1
                })
                .sum();
            assert_eq!(total, r.len(), "{range}: size mismatch");
        }
    }
}
