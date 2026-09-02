# vm-bandwidth-monitor

[![CI](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml)

**English** | [简体中文](README.zh-CN.md) | [日本語](README.ja-JP.md)

Real-time per-IPv4 bandwidth accounting and rate limiting for virtual machines
on a Linux bridge. An eBPF data plane (TC classifier, built with Aya) counts
and polices traffic per IP; a long-running daemon drives observation windows
and enforcement; a read-only terminal UI (`--ui`) shows live rates and
history. Configuration hot-reloads from `config.toml`. No database and no
HTTP server by default — optionally, cumulative counters are pushed to
VictoriaMetrics for historical trends.

- Counts only the IPv4 ranges configured in `config.toml`; everything else
  passes uncounted. Ranges are compiled into a minimal set of CIDR prefixes
  in an eBPF **LPM trie** (`MONITORED_IPS`), so range size never scales map
  usage. IPv6 is aggregated separately (counted, not limited, not per-IP).
- Every TAP interface gets TC ingress (VM TX, by source IP) and TC egress
  (VM RX, by destination IP). TAPs are detected by `tun_flags`, not by
  interface name; interfaces are rescanned periodically, so VMs can come and
  go without a restart.
- **Rate limiting**: each `(IP, direction)` keeps a rolling average window;
  when it crosses `threshold × trigger_ratio`, the selected algorithm's
  policy is installed into eBPF for `limit_duration`, then auto-recovers.
- **Hot reload**: editing `config.toml` applies transactionally (file watch +
  `SIGHUP`) with rollback to the last known-good config on any failure.
- The data plane only observes and polices; every error path is fail-open.

## Features

- Per-IP live and cumulative RX/TX bytes and packets, 1-second sampling
- Six selectable per-range policing algorithms (GCRA default) — see [examples/](examples/)
- Observation-triggered enforcement: NORMAL/LIMITED lifecycle with auto-recovery
- Per-IP policy overrides with field-level inheritance
- Transactional hot reload; invalid configs never interrupt monitoring
- Read-only terminal UI: range overview, per-IP detail, 1h/24h/7d/30d trends
- Optional VictoriaMetrics push (cumulative counters, standard `rate()` queries)
- Read-only IPC on a Unix socket; single data-plane owner by construction
- Graceful shutdown: removes only its own TC attachments, cleans map pins
- Fail-open everywhere: no anomaly in this program can break VM networking

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `vm-bandwidth-common` | `#[repr(C)]` types shared between eBPF and userspace (traffic/limit keys, SWL ring, algorithm constants) |
| `vm-bandwidth-ebpf` | TC classifier: counters + multi-algorithm policer (no_std, nightly) |
| `vm-bandwidth-core` | Pure logic: unit parsing, config validation, policy inheritance, windows, limiter state machine, IPC types. No aya dependency; unit-testable on any platform |
| `vm-bandwidth` | Runtime: daemon, eBPF loading, IPC server, hot reload, `--ui` client (binary `vm-bandwidth-monitor`) |

## Requirements

- Linux host with TC eBPF, per-CPU hash maps and `bpf_spin_lock` support.
  Kernel ≥ 6.6 attaches via TCX; older kernels fall back to netlink + clsact.
- Rust stable ≥ 1.89 plus **nightly** (`aya-build` compiles the eBPF part
  with `-Z build-std`)
- `bpf-linker`: `cargo install bpf-linker`
- Nightly `rust-src`: `rustup component add rust-src --toolchain nightly`

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo build --release
```

> The eBPF bytecode is produced by nightly's LLVM; bpf-linker only reads
> bitcode up to its own LLVM version. If the default nightly is newer (you
> get `Invalid record`), install an older matching nightly and build with
> `VM_BW_EBPF_TOOLCHAIN=nightly-<date> cargo build --release`.

Output: `target/release/vm-bandwidth-monitor`.

> Developer note: `AYA_BUILD_SKIP=1 cargo test` skips the eBPF build;
> `vm-bandwidth-core`'s pure-logic tests run on any platform.

## Quick start

Root is required (CAP_BPF + CAP_NET_ADMIN) and `/sys/fs/bpf` must be mounted
(usually already is).

```bash
# daemon (production form: under systemd)
sudo ./target/release/vm-bandwidth-monitor --config config.toml

# read-only terminal UI against the running daemon
./target/release/vm-bandwidth-monitor --ui
```

Startup sequence: parse and fully validate config → raise the fd limit →
compile ranges into CIDR prefixes in `MONITORED_IPS` → discover TAPs on the
bridge and attach TC → sample per second, drive windows and the limiter →
serve read-only IPC on `/run/vm-bandwidth-monitor.sock` → watch the config
file.

`SIGINT`/`SIGTERM` shut down cleanly (only this program's TC attachments are
removed; map pins and the socket are deleted). `SIGHUP` triggers one config
reload. The `--ui` client never loads eBPF, creates maps, or attaches TC —
the daemon is the only data-plane owner.

## Configuration (`config.toml`)

```toml
[network]
bridge = "br0"

[collector]
refresh_interval_ms = 1000        # sampling period (also the window tick)
interface_scan_interval_secs = 5  # TAP rescan period
map_max_entries = 8192            # TRAFFIC / LIMIT_POLICIES / LIMIT_STATE / SWL_LOG capacity

[display]
default_sort = "ip"               # initial sort in the --ui detail page: ip | rx | tx | total
# show_idle_ips = true            # enumerate every address of a range, including zero-traffic
                                  # ones (zero rows). Off by default; ranges larger than 4096
                                  # addresses are never enumerated

[metrics]                         # optional: historical trends (VictoriaMetrics)
enabled = false
url = "http://127.0.0.1:8428"
push_interval_secs = 60

[[ip_ranges]]
name = "VM-Network-1"
range = "10.30.8.1-10.30.8.16"

  [ip_ranges.policy]              # omit the block = monitor-only
  rx_threshold = "1Gbps"
  tx_threshold = "500Mbps"
  window = "5m"
  trigger_ratio = "80%"
  rx_limit = "500Mbps"
  tx_limit = "200Mbps"
  limit_duration = "30m"
  burst = "4MiB"

  [[ip_ranges.overrides]]         # per-IP exceptions, field-level merge
  ip = "10.30.8.3"
  rx_threshold = "2Gbps"
  rx_limit = "800Mbps"
```

Rules:

- Ranges are `START-END` only (no CIDR, wildcards, or reversed ranges) and
  must not overlap.
- `policy` is optional; omitting it leaves the range monitor-only.
  `rx_threshold`/`tx_threshold` and `rx_limit`/`tx_limit` are per-direction;
  `window`, `trigger_ratio`, `limit_duration`, `burst` are shared. A
  partially filled direction is rejected.
- Units: rates `100Mbps`/`1Gbps` (decimal), durations `5m`/`30m`/`1h`,
  percentages `80%`, bursts `4MiB` (binary). Integers only.
- Overrides must target an IP inside their range and be unique per range;
  unset fields inherit the range policy.
- `[metrics]` (optional, default off): pushes cumulative counters every
  `push_interval_secs` (5–3600). Loopback `http://` is allowed; remote
  endpoints require `https://` unless `allow_insecure_http = true`.

## Rate limiting

The limiter is **observation-triggered**: each `(IP, direction)` is judged
independently (RX and TX never sum together).

1. Trigger line = `threshold × trigger_ratio` (e.g. `1Gbps × 80% = 800Mbps`).
2. The daemon samples byte deltas per second into a rolling window; the
   window average is `bytes × 8 ÷ observed duration`.
3. Only after a **full** `window` has been observed, average ≥ trigger line
   arms the limiter. Instant spikes never trigger.
4. Arming installs the selected algorithm's policy into eBPF; the flow shows
   `LIMITED` (with remaining seconds) in the UI.
5. After `limit_duration` the policy is removed, the window is cleared, and
   the flow returns to NORMAL (it may re-arm later if traffic still exceeds
   the line — that is the intended behavior).

Enforcement is **policing**: conforming packets pass, excess packets are
dropped (`TC_ACT_SHOT`). No queuing/shaping (no HTB/TBF/netem) — limited
flows behave like loss, and TCP converges near the limit. Monitoring counters
sit before the policer, so the window average reflects *demand*; actual
delivery is in the policer verdict counters (`POLICER_STATS`, visible in the
UI's Dropped column).

### Algorithms

All six share the trigger layer and differ only in per-packet verdicts.
`rx_limit`/`tx_limit` are sustained-rate ceilings in every algorithm.
Runnable per-algorithm configs live in [examples/](examples/).

| Algorithm | `algorithm` value | Extra field | Burst behavior | Dataplane cost |
| --- | --- | --- | --- | --- |
| Token Bucket | `token_bucket` | `burst` | Bursts ≤ `burst` pass, then rate-limited | Very low |
| Leaky Bucket | `leaky_bucket` | `burst` | Bursts fill the queue level; overflow drops | Very low |
| Fixed Window | `fixed_window` | `limit_window` | Up to 2× rate across a window boundary | Very low |
| Sliding Window Counter | `sliding_window_counter` | `limit_window` | Weighted two-window approximation, no boundary burst | Very low |
| Sliding Window Log | `sliding_window_log` | `limit_window` | Exact window bytes; opt-in, scans a 1024-entry ring per packet | High |
| GCRA (default) | `gcra` | `burst` | Burst tolerance expressed as time tolerance | Very low |

Selection guidance: default to `gcra` or `token_bucket`; `leaky_bucket` for
the smoothest output; `sliding_window_counter` for window-quota semantics
without boundary bursts; `fixed_window` when you accept boundary bursts for
maximum simplicity; `sliding_window_log` only for low packet rates needing
exact window semantics (it requires
`[experimental] enable_sliding_window_log = true` and preallocates
`swl_map_max_entries` × ≈16.4 KiB of kernel memory).

### Policy fields

| Field | Scope | Meaning | Constraints |
| --- | --- | --- | --- |
| `rx_threshold` / `tx_threshold` | per direction | observation threshold | 100Kbps – 1Tbps |
| `rx_limit` / `tx_limit` | per direction | enforced rate once armed | 100Kbps – 1Tbps |
| `window` | shared | rolling observation window | > 0 (truncated at 3600 samples) |
| `trigger_ratio` | shared | trigger line as % of threshold | 1% – 100% |
| `limit_duration` | shared | enforcement duration, auto-recover after | > 0 |
| `burst` | shared | bucket capacity / GCRA tolerance (bucket algos + GCRA only) | ≤ 1GiB |
| `algorithm` | shared | policing algorithm, default `gcra` | one of six |
| `limit_window` | shared | window length (window algos only) | 1s – 60s |

Fields not applicable to the selected algorithm are ignored (so overrides can
inherit freely). Unknown algorithm names are rejected at load time; the data
plane treats an unknown tag as fail-open. Bounds exist so all eBPF integer
arithmetic provably never wraps.

### Hot-reload behavior of limit parameters

| Change | Effect |
| --- | --- |
| `rx_limit`/`tx_limit` while LIMITED | New rate immediately; algorithm state reset |
| `burst` / `limit_window` / `algorithm` while LIMITED | Immediate + state reset |
| `limit_duration` while LIMITED | `limited_until` recomputed from the original `limited_since`; may release immediately |
| `window` | Observation window cleared, re-accumulates |
| `threshold` / `trigger_ratio` | Current window kept; next evaluation uses the new line |
| Remove policy / override | Limits removed immediately, flow returns to NORMAL |
| Add / remove range | Whitelist and all state synchronized; removed range's limits, state and windows are cleaned |
| `network.bridge`, `collector.refresh_interval_ms`, `map_max_entries`, `swl_map_max_entries` | **Not hot-reloadable** — rejected with a restart hint |
| Invalid config | Entire reload rejected; last-known-good config kept; UI top bar shows FAILED with the reason |

## Operations

### Viewing and clearing limits

- **UI**: the overview's `Limited` column counts limited flows per range; the
  detail page shows per-flow `NORMAL`/`LIMITED` with remaining seconds.
- **Logs**: `journalctl -u vm-bandwidth-monitor | grep -iE "limited|trigger|expire"`
- **Dataplane proof** (authoritative): `bpftool map dump name LIMIT_POLICIES`
  and `... LIMIT_STATE` — both `[]` means no enforcement is active anywhere.

Clearing: remove the range's `[ip_ranges.policy]` block (all flows recover on
reload), raise limits via an override, shorten `limit_duration` (may release
immediately), restart (clears all windows and state), or simply wait for
auto-recovery. Removal is effective from the very next packet; windows then
re-accumulate and may re-arm if traffic still exceeds the trigger line.

### Terminal UI (`--ui`)

The overview lists each range with live and cumulative RX/TX, observed IP
count, and limited-flow count; the top bar shows bridge, TAP count, config
generation, and the last reload status. `Enter` opens the per-IP detail page
(live rates, window averages, effective policy, state, remaining time);
`trend` screens (per IP or whole range) cover 1h/24h/7d/30d with bandwidth /
packets switching. Column sets adapt to terminal width.

| Key | Page | Action |
| --- | --- | --- |
| `↑`/`↓`, `Enter`, `Esc` | all | navigate |
| `t` | overview/detail | range trend |
| `Enter` | detail | selected IP's trend (requires metrics) |
| `s` | detail | cycle sort (IP → RX → TX → total) |
| `←`/`→` or `1`–`4` | trend | switch window |
| `b` / `p` | trend | bandwidth / packets |
| `r` | overview/detail | refresh now |
| `q` | overview/detail | quit |

### Historical trends (VictoriaMetrics)

```bash
cd dist && docker compose up -d     # single node on 127.0.0.1:8428, 35-day retention
```

Then set `[metrics] enabled = true` (hot-reloadable). Data model: four
cumulative counters per IP (`vmbw_{rx,tx}_{bytes,packets}_total`, labels
`ip`/`range`), eight policer verdict counters for limited flows
(`vmbw_policer_{rx,tx}_{passed,dropped}_{bytes,packets}_total` — the actual
delivered/dropped volume), and four process-level ops counters
(`vmbw_tap_attach_failures_total`, `vmbw_metrics_push_{successes,failures,skipped}_total`).
Counter resets across daemon restarts are handled by standard `rate()`
semantics.

## Design notes

- **One eBPF object, attached to every TAP**: loaded once (verifier runs
  once); the same programs attach per TAP via TCX (≥ 6.6) or netlink clsact.
  Seven maps (LPM whitelist, IPv4/IPv6 counters, policies, states, SWL log,
  policer stats) are shared by construction.
- **VLAN/QinQ**: up to two 802.1Q/802.1ad tags (compile-time bound) are
  stripped; deeper tags, truncated tags and non-IP payloads fail open.
- **IPv6 is keyed by TAP**, not address — privacy-address rotation cannot
  exhaust the counter map.
- Attachments are owned precisely: only this program's TC filters are ever
  removed; shared qdiscs are never deleted. Attach failures retry with
  exponential backoff.
- Counters are monotonic; userspace computes rates from adjacent-sample
  deltas. Wrap/reset/TAP-rebuild periods read as zero — never negative
  bandwidth, never false triggers.
- Idle counter reclamation: keys unchanged for ~5 minutes are evicted and
  rebuilt by the data plane on the next packet.
- A single engine task owns all mutable state; IPC/watchers/signals talk to it
  over bounded channels (single writer, no shared mutable locks).
- A lock file prevents double-start; the IPC socket is created 0600.

## Known limitations

- IPv6 is aggregated only (no limiting, no per-IP split); ARP/non-IP traffic
  is not counted; ports/connections/payloads are never parsed.
- Frames larger than 65535 bytes (e.g. GSO aggregates) are not policed; they
  pass and are counted in the `oversized` observability counters.
- When `map_max_entries` is exhausted, new flows are not counted and new
  policies cannot install (packets still pass; logged).
- Cumulative traffic counts from daemon start (maps rebuild on restart).
- Enforcement is policing: excess packets are dropped, never buffered or
  shaped.

## License

This project is dual-licensed by component:

- **Userspace crates** (`vm-bandwidth`, `vm-bandwidth-core`, `vm-bandwidth-common`) — [MIT](LICENSE)
- **eBPF program** (`vm-bandwidth-ebpf`) — [GPL-2.0-only](vm-bandwidth-ebpf/LICENSE),
  because it uses GPL-only kernel helpers (`bpf_spin_lock`); the Linux kernel
  requires GPL-compatible programs to call them.

## Documentation

- [docs/kernel-validation.md](docs/kernel-validation.md) — one-off kernel/dataplane validation playbook
- [docs/production-validation.md](docs/production-validation.md) — production validation records
- [examples/](examples/) — runnable per-algorithm rate-limiting configs
