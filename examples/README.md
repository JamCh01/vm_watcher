# Rate-Limiting Algorithm Examples / 限速算法示例

Each `.toml` here is a **complete, runnable daemon config** demonstrating one
policing algorithm. Copy one, adjust `bridge` / `range` / rates, and load it
(`vm-bandwidth --config your.toml` or systemd + hot reload).

每个 `.toml` 都是一份**完整可直接运行**的配置示例，演示一种限速算法。复制后修改
`bridge` / `range` / 速率，直接加载即可（`vm-bandwidth --config your.toml`
或 systemd 部署后热加载）。

## Algorithms / 算法一览

| File / 文件 | Algorithm / 算法 | State per flow / 每流状态 | Notes / 说明 |
|---|---|---|---|
| `gcra.toml` | GCRA (default / 默认) | 1 word | Virtual-scheduling TAT policer; smooth, cheapest. 虚调度 TAT 策略器，最平滑、开销最低 |
| `token_bucket.toml` | Token Bucket | 1 word | Classic refill/spend policer. 经典令牌桶 |
| `leaky_bucket.toml` | Leaky Bucket | 1 word | Dual view of token bucket. 令牌桶对偶视角 |
| `fixed_window.toml` | Fixed Window | 2 counters | Hard byte budget per window; up to 2× at boundaries. 固定窗口硬预算，边界处可达 2 倍 |
| `sliding_window_counter.toml` | Sliding Window Counter | 2 counters | Weighted two-window approximation, O(1)/packet. 双窗口加权近似 |
| `sliding_window_log.toml` | Sliding Window Log | 16.4 KiB map entry | Exact window, opt-in, scans log per packet. 精确窗口，需显式开启，每包扫日志 |

## Enforcement model (all algorithms) / 触发模型（所有算法通用）

The limiter is **observation-triggered, not always-on**: each (IP, direction)
is observed over a rolling `window`; when traffic crosses
`threshold × trigger_ratio` the policy **arms** and enforces `rx_limit` /
`tx_limit` with the selected algorithm for `limit_duration`, then auto-recovers.
`burst` (GCRA/buckets) or `limit_window` (window algorithms) shapes the
enforcement itself.

限速器是**观测触发式**而非全程生效：每个（IP，方向）在滚动 `window` 上被观测，
流量越过 `threshold × trigger_ratio` 触发线后策略**武装**，按所选算法把速率限制到
`rx_limit` / `tx_limit`，持续 `limit_duration` 后自动恢复。`burst`
（GCRA/桶类）或 `limit_window`（窗口类）决定武装期间的执法形态。

Per-IP exceptions use `[[ip_ranges.overrides]]` inside the range; unset fields
inherit the range policy. Full reference: README § Configuration.

单 IP 例外用段内 `[[ip_ranges.overrides]]`；未写字段继承段策略。完整字段参考见
README 配置章节。
