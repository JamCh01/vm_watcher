//! Near-O(1) rolling byte window used for threshold detection.
//!
//! The window is a fixed-size ring buffer of per-tick byte samples. Each tick the engine
//! adds the bytes seen since the previous tick; the oldest sample is evicted at the same
//! time, so both the memory footprint and the per-tick work are constant.
//!
//! The window deliberately knows nothing about IPs or directions — one instance tracks one
//! (IP, direction) stream. It also knows nothing about monotonic clocks: the engine drives
//! it with one `add` per tick and the window counts ticks, which keeps it fully testable.

/// Upper bound on ring size so an unusually large window cannot blow up memory.
pub const MAX_SAMPLES: usize = 3600;

#[derive(Debug, Clone)]
pub struct RollingWindow {
    ring: Vec<u64>,
    /// Next slot to overwrite (the oldest sample).
    head: usize,
    /// Sum of all samples currently in the ring.
    total: u64,
    /// Number of ticks observed since the last reset (saturates at ring length).
    observed: u64,
    /// Seconds represented by one tick.
    tick_secs: u64,
}

impl RollingWindow {
    /// A window covering `window_secs` with one sample per `tick_secs`.
    ///
    /// If `window_secs / tick_secs` exceeds [`MAX_SAMPLES`] the ring is capped; the window
    /// then effectively covers `MAX_SAMPLES * tick_secs` (documented limitation for
    /// very large windows).
    pub fn new(window_secs: u64, tick_secs: u64) -> Self {
        let tick_secs = tick_secs.max(1);
        let samples = (window_secs / tick_secs).max(1) as usize;
        let samples = samples.clamp(1, MAX_SAMPLES);
        Self {
            ring: vec![0; samples],
            head: 0,
            total: 0,
            observed: 0,
            tick_secs,
        }
    }

    /// Number of samples the ring holds.
    pub fn samples(&self) -> usize {
        self.ring.len()
    }

    /// Seconds of traffic one full ring represents.
    pub fn capacity_secs(&self) -> u64 {
        self.ring.len() as u64 * self.tick_secs
    }

    /// Add the bytes seen during this tick and advance the ring.
    pub fn add(&mut self, delta_bytes: u64) {
        // Evict the oldest sample (the slot we are about to overwrite).
        self.total = self.total.saturating_sub(self.ring[self.head]);
        self.ring[self.head] = delta_bytes;
        self.total = self.total.saturating_add(delta_bytes);
        self.head = (self.head + 1) % self.ring.len();
        if self.observed < self.ring.len() as u64 {
            self.observed += 1;
        }
    }

    /// True once a full ring of samples has been observed since the last reset. Trigger
    /// decisions are only valid when this holds.
    pub fn is_full(&self) -> bool {
        self.observed >= self.ring.len() as u64
    }

    /// Average bits per second over the observed window.
    ///
    /// `average = window_bytes * 8 / actual_window_duration`. The denominator is the time
    /// actually observed (capped at the ring capacity), so a partially-filled window never
    /// reports an inflated rate.
    pub fn average_bps(&self) -> f64 {
        let secs = self.observed.min(self.ring.len() as u64) * self.tick_secs;
        if secs == 0 {
            return 0.0;
        }
        self.total as f64 * 8.0 / secs as f64
    }

    /// Total bytes currently in the window.
    pub fn total_bytes(&self) -> u64 {
        self.total
    }

    /// Clear all samples (used when a limit expires or the window config changes).
    pub fn reset(&mut self) {
        self.ring.fill(0);
        self.total = 0;
        self.observed = 0;
        self.head = 0;
    }

    /// Resize to a new window length, discarding history (§20: a window change always
    /// restarts accumulation rather than migrating old samples).
    pub fn resize(&mut self, window_secs: u64, tick_secs: u64) {
        *self = Self::new(window_secs, tick_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_reports_average() {
        // 5-second window, 1-second ticks.
        let mut w = RollingWindow::new(5, 1);
        assert_eq!(w.samples(), 5);
        assert!(!w.is_full());
        assert_eq!(w.average_bps(), 0.0);

        // 1000 bytes/sec sustained => 1000*8 = 8000 bps.
        for _ in 0..5 {
            w.add(1000);
        }
        assert!(w.is_full());
        assert_eq!(w.total_bytes(), 5000);
        assert!((w.average_bps() - 8000.0).abs() < 1e-9);
    }

    #[test]
    fn evicts_oldest_sample() {
        let mut w = RollingWindow::new(3, 1);
        w.add(100);
        w.add(200);
        w.add(300);
        assert_eq!(w.total_bytes(), 600);
        // Adding a fourth sample evicts the first (100).
        w.add(400);
        assert_eq!(w.total_bytes(), 900);
        assert!(w.is_full());
    }

    #[test]
    fn partial_window_average_uses_observed_time() {
        let mut w = RollingWindow::new(10, 1);
        w.add(1000);
        w.add(1000);
        // 2000 bytes over 2 observed seconds => 2000*8/2 = 8000 bps, not /10.
        assert!((w.average_bps() - 8000.0).abs() < 1e-9);
        assert!(!w.is_full());
    }

    #[test]
    fn reset_clears() {
        let mut w = RollingWindow::new(3, 1);
        w.add(1);
        w.add(1);
        w.add(1);
        assert!(w.is_full());
        w.reset();
        assert!(!w.is_full());
        assert_eq!(w.total_bytes(), 0);
        assert_eq!(w.average_bps(), 0.0);
    }

    #[test]
    fn resize_discards_history() {
        let mut w = RollingWindow::new(5, 1);
        for _ in 0..5 {
            w.add(10);
        }
        assert!(w.is_full());
        w.resize(10, 1);
        assert!(!w.is_full());
        assert_eq!(w.total_bytes(), 0);
        assert_eq!(w.samples(), 10);
    }

    #[test]
    fn caps_samples() {
        let w = RollingWindow::new(1_000_000, 1);
        assert_eq!(w.samples(), MAX_SAMPLES);
    }

    #[test]
    fn zero_window_is_safe() {
        let mut w = RollingWindow::new(0, 0);
        assert!(w.samples() >= 1);
        w.add(5);
        assert!(w.average_bps() >= 0.0);
    }
}
