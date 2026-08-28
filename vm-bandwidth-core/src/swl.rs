//! Userspace reference model of the eBPF sliding-window-log policer.
//!
//! The data-path implementation lives in `vm-bandwidth-ebpf` (swl_police) and cannot
//! be unit-tested directly; this model mirrors its semantics exactly — bounded ring,
//! window sum over entries newer than `now - window`, overwrite-oldest when full — so
//! the algorithm's behavior (including its known high-PPS leniency) is pinned by
//! tests and documented numbers.
//!
//! Approximate accuracy boundary: the ring holds [`SWL_LOG_CAP`] entries, so a flow
//! above roughly `SWL_LOG_CAP / window` packets per second starts overwriting entries
//! that are still inside the window. The model then UNDER-counts window usage and
//! policing becomes lenient — this is the documented trade of the algorithm, and the
//! reason it must be explicitly enabled (see `[experimental]` in the config).
//!
//! Mirrored quirk: the window bound is `now.wrapping_sub(window)`, so during the first
//! `window` of uptime the bound wraps huge and no entry matches — SWL policing is
//! lenient for that initial stretch, exactly like the data path. Tests therefore run
//! on timestamps past one window.

use vm_bandwidth_common::SWL_LOG_CAP;

/// One logged packet: arrival time (ns) and wire length (bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Entry {
    ts_ns: u64,
    len: u64,
}

#[derive(Debug, Clone)]
pub struct SwlModel {
    ring: Vec<Entry>,
    head: usize,
}

impl Default for SwlModel {
    fn default() -> Self {
        Self::new()
    }
}

impl SwlModel {
    pub fn new() -> Self {
        Self {
            ring: vec![Entry::default(); SWL_LOG_CAP],
            head: 0,
        }
    }

    /// Bytes currently inside the window (what the eBPF scan computes per packet).
    pub fn window_used(&self, now_ns: u64, window_ns: u64) -> u64 {
        let bound = now_ns.wrapping_sub(window_ns);
        self.ring
            .iter()
            .filter(|e| e.ts_ns > bound)
            .map(|e| e.len)
            .sum()
    }

    /// Policer step mirroring `swl_police`: returns true when the packet CONFORMS
    /// (is admitted). Non-conforming packets are not logged, matching the data path.
    pub fn police(&mut self, now_ns: u64, len: u64, window_ns: u64, allowance_bytes: u64) -> bool {
        if window_ns == 0 {
            return true;
        }
        let used = self.window_used(now_ns, window_ns);
        let conform = used.saturating_add(len) <= allowance_bytes;
        if conform {
            self.ring[self.head] = Entry { ts_ns: now_ns, len };
            self.head = (self.head + 1) % self.ring.len();
        }
        conform
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;
    /// Timestamps start past one full window so the wrapping-bound boot quirk (which
    /// the model shares with the data path) does not apply inside the scenarios.
    const BASE: u64 = 1000 * SEC;

    #[test]
    fn exact_below_ring_capacity() {
        // Below the overwrite boundary the log is exact: exactly `allowance` bytes
        // are admitted per window, byte for byte.
        let mut m = SwlModel::new();
        let allowance = 1000;
        let mut admitted = 0u64;
        for i in 0..1500u64 {
            if m.police(BASE + i * 1000, 1, SEC, allowance) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, allowance);
    }

    #[test]
    fn window_expiry_is_exact() {
        let mut m = SwlModel::new();
        // Fill 500 bytes, window 1s.
        for _ in 0..500 {
            assert!(m.police(BASE, 1, SEC, 600));
        }
        // Still inside the window: only 100 more fit.
        for _ in 0..100 {
            assert!(m.police(BASE + SEC / 2, 1, SEC, 600));
        }
        assert!(!m.police(BASE + SEC / 2, 1, SEC, 600));
        // Past the window the first batch expires, but the mid-window batch (100
        // bytes at BASE + SEC/2) is still inside: 500 of budget left, not 600.
        for _ in 0..500 {
            assert!(m.police(BASE + SEC + 1, 1, SEC, 600));
        }
        assert!(!m.police(BASE + SEC + 1, 1, SEC, 600));
    }

    #[test]
    fn ring_saturation_is_lenient_not_strict() {
        // Above roughly CAP/window packets per second the ring overwrites entries
        // still inside the window: usage is under-counted and policing admits MORE
        // than the exact allowance. This pins the documented trade instead of
        // pretending the algorithm is exact at any rate.
        let mut m = SwlModel::new();
        let allowance = 1500u64; // bytes
        let mut admitted = 0u64;
        // 3000 one-byte packets well inside one window: far above CAP (1024).
        for i in 0..3000u64 {
            if m.police(BASE + i * 100, 1, 10 * SEC, allowance) {
                admitted += 1;
            }
        }
        assert!(
            admitted > allowance,
            "expected lenient over-admission at high PPS, got {admitted}"
        );
        // The log can never hold more than CAP entries' worth of usage.
        assert!(m.window_used(BASE + 3000 * 100, 10 * SEC) <= SWL_LOG_CAP as u64);
    }

    #[test]
    fn boundary_rate_documented() {
        // At exactly CAP packets per window the ring is full but nothing in-window is
        // overwritten yet: accounting is still exact.
        let mut m = SwlModel::new();
        let allowance = SWL_LOG_CAP as u64 * 2;
        for i in 0..SWL_LOG_CAP as u64 {
            assert!(
                m.police(BASE + i, 1, SEC, allowance),
                "packet {i} should fit"
            );
        }
        assert_eq!(
            m.window_used(BASE + SWL_LOG_CAP as u64, SEC),
            SWL_LOG_CAP as u64
        );
    }

    #[test]
    fn non_conforming_packets_are_not_logged() {
        let mut m = SwlModel::new();
        assert!(m.police(BASE, 100, SEC, 100));
        assert!(!m.police(BASE + 1, 50, SEC, 100)); // would exceed: dropped, NOT logged
        assert_eq!(m.window_used(BASE + 1, SEC), 100);
    }
}
