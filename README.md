# vm-bandwidth-monitor

[![CI](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml)

实时统计 Linux Bridge（`br0`）下虚拟机按 IPv4 地址划分的网络带宽，并可对 IP 段 / 单个
IP 做**限速**——限速算法可按段选择：令牌桶、漏桶、固定窗口、滑动窗口计数器、
滑动窗口日志、GCRA（默认）。eBPF (TC/SchedClassifier, Aya) 采集与执行，长期运行 daemon +
只读 `--ui` 终端界面，`config.toml` 热加载。默认无数据库、无 HTTP 服务；可选把
累计流量推送到 VictoriaMetrics，在 `--ui` 里查看任意 IP 的历史趋势。

- 只统计 `config.toml` 配置的 `开始IP-结束IP` 地址段内的 IPv4，其余一律放行不计数。
  白名单是 eBPF **LPM 前缀字典树**：段被分解为最少的 CIDR 前缀写入
  `MONITORED_IPS`（最长前缀匹配判定成员），段大小不再逐地址枚举、与 map 占用解耦。
  IPv6 另行聚合统计（首页末尾的 `IPv6` 行）：只计数、不限速、无按 IP 拆分。
- 每个 TAP 接口挂载 TC ingress（VM TX，按源 IP）与 TC egress（VM RX，按目标 IP）。
- TAP 识别不依赖接口名（支持纯数字接口名），按 `tun_flags` 判定；周期重扫，
  新增/删除 VM 无需重启。
- **限速**：每个 `(IP, 方向)` 维护滑动窗口平均，达到 `threshold × trigger_ratio`
  后进入 LIMITED，向 eBPF 下发限速策略（所选算法 + 参数）；持续 `limit_duration` 后
  自动恢复。
- **热加载**：修改 `config.toml` 自动生效（文件监听 + `SIGHUP`）。事务式应用：
  先生成纯变更计划（限速器不改自身状态），按“白名单新增 → 解除（先策略后状态）
  → 安装（先状态后策略，策略写入才是生效标志）→ 白名单移除”执行全部 map 操作，
  全部成功才提交限速器状态、切换配置并递增 generation；任一 map 操作失败则逆向
  回滚已执行的部分并保持上一份配置（last-known-good）。运行期触发/解除限速失败时
  同样回滚并把相关流复位为 NORMAL，等待下一次越阈重试。成功后立即重采集一次：
  IPC 快照与限流状态在新配置下重建，消除旧快照×新配置的混合窗口。文件监听器
  （inotify）报错会上报引擎：记录日志、计数并经 IPC/`--ui` 顶栏暴露（热加载可能已失效）。
- eBPF 数据面只做观察计数与限速 policing，任何异常路径一律放行（fail-open）。
- **历史趋势**（可选）：`[metrics]` 启用后，daemon 周期推送每 IP 的累计字节/包数
  到 VictoriaMetrics；`--ui` 详情页选中 IP 按 `Enter` 查看 1h / 24h / 7d / 30d 的
  带宽与发包量趋势。

## 工作区结构

| crate | 说明 |
| --- | --- |
| `vm-bandwidth-common` | eBPF 与用户态共享的 `#[repr(C)]` 类型（`TrafficKey/Value`、`LimitKey/Policy/State`、`SwlRing`、算法常量、方向常量） |
| `vm-bandwidth-ebpf` | TC classifier：计数 + 多算法 policer（no_std，nightly 编译） |
| `vm-bandwidth-core` | 纯逻辑：单位解析、配置解析/校验、策略继承、滑动窗口、限速状态机、IPC 类型。不依赖 aya，任意平台可单测 |
| `vm-bandwidth` | 运行时：daemon、eBPF 装载、IPC 服务、热加载、`--ui` 客户端（bin `vm-bandwidth-monitor`） |

## 构建要求

- Linux 宿主机（内核需支持 TC eBPF、per-CPU hash map 与 `bpf_spin_lock`；≥6.6 使用
  TCX 挂载，更旧内核走 netlink + clsact）
- Rust stable ≥ 1.89 + **nightly**（`aya-build` 用 `-Z build-std` 编译 eBPF 部分）
- `bpf-linker`：`cargo install bpf-linker`
- nightly 需要 `rust-src`：`rustup component add rust-src --toolchain nightly`

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo build --release
```

> eBPF 字节码由 nightly 的 LLVM 生成，bpf-linker 只能读懂不高于自己 LLVM 版本的位码。
> 若默认 `nightly` 的 LLVM 比本机 bpf-linker 新（报 `Invalid record`），安装一个 LLVM
> 版本匹配的旧 nightly，然后：`VM_BW_EBPF_TOOLCHAIN=nightly-<日期> cargo build --release`。

产物：`target/release/vm-bandwidth-monitor`

> 开发机技巧：`AYA_BUILD_SKIP=1 cargo test` 可跳过 eBPF 编译；`vm-bandwidth-core` 的
> 纯逻辑单测（配置/策略/窗口/限速/单位/IPC）不需要 Linux，直接 `cargo test -p vm-bandwidth-core`。

## 运行

需要 root（CAP_BPF + CAP_NET_ADMIN），且 `/sys/fs/bpf` 已挂载（通常默认挂载）。

### daemon（默认）

前台长期运行，由 systemd 管理；不启动 TUI，没有终端也不会退出。

```bash
sudo ./target/release/vm-bandwidth-monitor --config /etc/vm-bandwidth-monitor/config.toml
```

启动流程：读取并完整校验配置 → 提升文件描述符上限 → 把各段分解为 CIDR 前缀写入
LPM 字典树白名单 `MONITORED_IPS` → 发现 br0 下的 TAP 并挂载 TC → 每秒采样计算带宽、驱动滑动窗口与
限速 → 在 `/run/vm-bandwidth-monitor.sock` 提供只读 IPC → 监听配置变化。

正确处理 `SIGINT`/`SIGTERM`：停止计算与 reload、停 IPC、仅移除本程序创建的 TC
挂载、删除 map pin 与 socket、正常退出。`SIGHUP` 触发一次配置 reload。

### `--ui`（只读客户端）

```bash
./target/release/vm-bandwidth-monitor --ui
```

通过 Unix socket 连接**正在运行的 daemon** 展示实时数据。它**绝不**重新加载 eBPF、
不创建 map、不挂载 TC，也不运行独立的限速器——数据面只有一个所有者（daemon）。

配置非法（格式错误、名称为空/重复、范围反向/重叠、策略不完整、单位非法、override
越界）时拒绝启动或拒绝该次 reload，并指明出错的配置项。

## 配置（config.toml）

```toml
[network]
bridge = "br0"

[collector]
refresh_interval_ms = 1000        # 采样周期，也是滑动窗口的采样粒度
interface_scan_interval_secs = 5  # TAP 重扫周期
map_max_entries = 8192            # TRAFFIC / LIMIT_POLICIES / LIMIT_STATE / SWL_LOG 容量

[display]
default_sort = "ip"               # --ui 详情页初始排序: ip | rx | tx | total

[metrics]                         # 可选：历史趋势（VictoriaMetrics）
enabled = false
url = "http://127.0.0.1:8428"
push_interval_secs = 60

[[ip_ranges]]
name = "VM-Network-1"
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
```

- 只支持 `开始IP-结束IP`；不支持 CIDR、通配符、反向范围。IP 段之间不允许重叠。
- `policy` 可选：不写即只监控不限速。`rx_threshold/tx_threshold`、`rx_limit/tx_limit`
  按方向独立；`window`、`trigger_ratio`、`limit_duration`、`burst` 两个方向共用。
  某方向只配置了部分字段（不完整）会被拒绝。
- 单位：速率 `100Mbps`/`1Gbps`（1000 进制）；时长 `5m`/`30m`/`1h`；百分比 `80%`；
  突发 `4MiB`（二进制）。一律整数，不接受浮点。
- `[[ip_ranges.overrides]]` 覆盖单个 IP：未写的字段继承所属段的 `policy`；override 的
  IP 必须落在所属段内，且同一段内不可重复。
- 触发线 = `threshold × trigger_ratio`。判定的是**过去完整 `window` 的平均带宽**，
  不是瞬时采样；窗口观察满后才允许首次触发。
- `[metrics]` 可选（默认关闭）：`enabled = true` 时 daemon 每 `push_interval_secs`
  （5..=3600）秒向 `url` 推送一次累计计数器；`url` 仅支持 `http://`（内置客户端
  无 TLS，本机部署即可）。未启用时不产生任何出站请求。

## 安全前提（反 IP 欺骗）

本程序按报文**源地址**计数与限速，但没有 VM 清单、也没有可信的 TAP→IP 绑定来源，
因此**无法**验证某个源地址是否属于它到达的 TAP。源地址反欺骗必须由**外部**强制，
这是运行本程序的硬性前提，配置里以 `[security]` 显式确认（未确认时 daemon 拒绝启动）：

```toml
[security]
ip_ownership = "external"                 # 目前唯一支持的模式
acknowledge_external_anti_spoofing = true # 确认外部反欺骗已部署
```

未部署反欺骗时的风险：VM 可伪造其他受监控 IP 的源地址——污染其统计/计费，或消耗
其限速预算（触发其 LIMITED）。本程序的 `LimitKey` 故意不含 ifindex（同 IP 跨 TAP
共享一份预算），把 ifindex 加进 key 并不能解决欺骗，只是拆分预算。

**部署检查清单**（由平台侧负责，逐项确认后再设 `acknowledge = true`）：

1. 每台 VM 的 TAP 是否限制其可用源 IPv4（Linux bridge + `ebtables/nftables`
   `ether saddr`/`ip saddr` 绑定，或 Proxmox 防火墙的 `-ipfilter`/IPSet）；
2. IPv6 源地址是否同样受控（隐私地址/SLAAC 轮换使逐地址绑定更困难，至少限制
   前缀范围）；
3. 规则对 TAP 重建/迁移后仍然生效（规则挂在接口名还是桥端口上，谁负责同步）；
4. 变更由谁负责：虚拟化平台、宿主防火墙，还是本配置——写进运维文档。

隔离双 TAP 欺骗验证方案见 `docs/kernel-validation.md`（只在一次性测试环境执行）。
IPC `Status` 暴露 `anti_spoof_mode`/`anti_spoof_enforced_by_program`（当前恒为
false：非本程序强制）/`anti_spoof_acknowledged`，供工具核对契约。真正的严格
TAP-IP 绑定（所有权数据源、VM 创建/迁移/换 IP 的同步、ifindex 变化、失败语义）
是独立设计课题，不在当前范围内。

## 限速策略配置详解

### 快速开始：给一个段启用限速

在对应的 `[[ip_ranges]]` 下加一个 `[ip_ranges.policy]` 块，保存即热生效（无需重启）：

```toml
[[ip_ranges]]
name = "VM-Network-1"
range = "10.30.8.1-10.30.8.16"

  [ip_ranges.policy]
  rx_threshold   = "1Gbps"    # RX 持续超过触发线就限速（阈值）
  tx_threshold   = "500Mbps"  # TX 同理，两个方向完全独立判定
  window         = "5m"       # 观察窗口：用过去完整 5 分钟的平均带宽判断
  trigger_ratio  = "80%"      # 触发线 = threshold × 80%（RX 即 800Mbps）
  rx_limit       = "500Mbps"  # 触发后 RX 被 GCRA 限制到的速率
  tx_limit       = "200Mbps"  # 触发后 TX 被限制到的速率
  limit_duration = "30m"      # 限速持续 30 分钟，到期自动恢复并重新观察
  burst          = "4MiB"     # 允许的瞬时突发量（约 4MiB 的积压额度）
```

默认算法是 **GCRA**（v2 行为完全不变）。想换算法就加一行 `algorithm = "..."`，
见下文《限速算法》。

**不写 `[ip_ranges.policy]` = 该段只监控、不限速。** 想关闭限速，把 policy 块删掉保存即可，
热加载会立即移除该段所有流的限速并恢复 NORMAL。

### 限速算法

`algorithm` 决定触发后数据面用哪种算法执行。六种算法覆盖经典限速模型；所有算法共用
同一套触发层（`threshold` / `window` / `trigger_ratio` / `limit_duration`），只在
"如何判定单个包"上不同。`rx_limit`/`tx_limit` 在每种算法里都是**持续速率上限**。

| 算法 | `algorithm` 值 | 额外参数 | 突发处理 | 平滑度 | 数据面开销 | 适合场景 |
| --- | --- | --- | --- | --- | --- | --- |
| 令牌桶 Token Bucket | `token_bucket` | `burst` | 允许 ≤ `burst` 的突发，之后按速率放行 | 中 | 极低（每包 2 个计数器） | 通用默认之一：容忍突发、长期均速，最接近常见云厂商带宽语义 |
| 漏桶 Leaky Bucket | `leaky_bucket` | `burst` | 突发进入"队列水位"，超容量即丢 | 高（输出最平滑） | 极低（每包 2 个计数器） | 要求速率曲线平滑、压制突发尖峰（如保护下游脆弱链路） |
| 固定窗口计数器 Fixed Window | `fixed_window` | `limit_window` | 窗口边界处最多可通过 2 倍速率（临界突发） | 低 | 极低（每包 2 个计数器） | 与计费/配额周期对齐的粗粒度管控；实现最简 |
| 滑动窗口计数器 Sliding Window Counter | `sliding_window_counter` | `limit_window` | 无真正突发概念，窗口内按字节配额 | 较高 | 极低（每包 3 个计数器） | 固定窗口的平滑版：消除窗口边界 2 倍突发；MiB 统计粒度 |
| 滑动窗口日志 Sliding Window Log | `sliding_window_log` | `limit_window` | 无；精确统计窗口内字节 | 最高（精确） | 高（每包扫描 1024 条日志） | 低包率、要求精确窗口语义的流；高包率下日志环溢出会偏宽松 |
| GCRA（默认） | `gcra` | `burst` | ≤ `burst` 的突发容忍（以时间容忍度表达） | 高 | 极低（每包 1 个 TAT） | ATM/电信经典算法；对突发敏感、要求严格长期速率的场景 |

**选型建议**：拿不准就用默认的 `gcra` 或 `token_bucket`——前者突发容忍以时间表达、
对持续超速最敏感，后者以字节表达、语义最直观。要平滑压峰选 `leaky_bucket`；
窗口配额语义（"每 N 秒最多 X 字节"）选 `sliding_window_counter`；`fixed_window`
接受边界突发换取最简实现；`sliding_window_log` 只建议用于低包率的精确管控。

各算法配置示例（只列与默认不同的字段；`rx_threshold`/`window`/`trigger_ratio`/
`limit_duration` 等触发层字段所有算法相同，见上文快速开始）：

**令牌桶**——桶容量 `burst`，按 `rx_limit` 速率回填：

```toml
  [ip_ranges.policy]
  algorithm = "token_bucket"
  rx_limit  = "500Mbps"   # 令牌回填速率（= 持续速率上限）
  tx_limit  = "200Mbps"
  burst     = "4MiB"      # 桶容量（字节）：空闲积累的突发额度
  # + 触发层字段：rx_threshold / tx_threshold / window / trigger_ratio / limit_duration
```

**漏桶**——水位按 `rx_limit` 速率漏出，容量 `burst`：

```toml
  [ip_ranges.policy]
  algorithm = "leaky_bucket"
  rx_limit  = "500Mbps"   # 漏出速率
  tx_limit  = "200Mbps"
  burst     = "2MiB"      # 桶容量：容量越小，对突发越严格
```

**固定窗口计数器**——每个 `limit_window` 内放行 `limit × 窗口` 字节：

```toml
  [ip_ranges.policy]
  algorithm    = "fixed_window"
  rx_limit     = "500Mbps"  # 窗口配额 = 500Mbps × 5s = 312.5MB / 窗口
  tx_limit     = "200Mbps"
  limit_window = "5s"       # 窗口从该流触发后的首包开始对齐
```

**滑动窗口计数器**——同上但用加权双窗口消除边界突发：

```toml
  [ip_ranges.policy]
  algorithm    = "sliding_window_counter"
  rx_limit     = "500Mbps"
  tx_limit     = "200Mbps"
  limit_window = "5s"
```

**滑动窗口日志**——精确记录窗口内每个包的到达时间与长度（环形 1024 条）：

```toml
  [ip_ranges.policy]
  algorithm    = "sliding_window_log"
  rx_limit     = "100Mbps"   # 精确窗口语义适合较低的速率/包率
  tx_limit     = "50Mbps"
  limit_window = "10s"
```

**GCRA（默认，不写 `algorithm` 即此算法）**：

```toml
  [ip_ranges.policy]
  algorithm = "gcra"      # 可省略
  rx_limit  = "500Mbps"   # 虚拟调度的发射速率
  tx_limit  = "200Mbps"
  burst     = "4MiB"      # 突发容忍量（换算为时间容忍度）
```

实现细节与精度说明：

- 桶类状态以"字节 × 10⁹"存储，低速率的亚字节回填不会丢失精度。
- 窗口类算法的配额计算用 `limit × 整数秒`，统计按 MiB 粒度取整：极小配额
  （窗口配额 < 1MiB）会退化为接近固定窗口行为。
- 滑动窗口日志的环形缓冲固定 1024 条：包率高于约 `1024 / limit_window` 条/秒时
  旧条目被覆盖、窗口字节统计偏低（判定偏宽松）；每包还要在自旋锁内扫描整个环。
  因此它是**实验性算法**：配置 `algorithm = "sliding_window_log"` 前必须显式打开
  `[experimental] enable_sliding_window_log = true`（否则拒绝加载）。
  内存代价：`SWL_LOG` 按 `collector.swl_map_max_entries`（默认 256，独立于
  `map_max_entries`）在加载时**预分配**，每条 ≈16.4 KiB——估算公式
  `条数 × 16.4 KiB`（256 条 ≈ 4 MiB；误用 8192 条 ≈ 134 MiB 内核内存）。
  语义由用户态参考模型（`vm-bandwidth-core/src/swl.rs`）与测试钉死，含开机后
  首个窗口内环绕边界导致的短暂宽松。
- 固定/滑动窗口的时间窗锚定在触发后该流的首个包，不与墙上时钟对齐。
- 未知 `algorithm` 值在配置校验期即被拒绝；数据面遇到未知算法标签一律放行
  （fail-open）。
- RFC 2697/2698 的 srTCM/trTCM（两速率三色标记）不在选项之列：它们输出
  绿/黄/红三色标记而非"放行/丢弃"二值判定，与本项目 policing 模型不符。

### 字段说明

| 字段 | 归属 | 含义 | 单位 | 约束 |
| --- | --- | --- | --- | --- |
| `rx_threshold` / `tx_threshold` | 方向独立 | 阈值，与 `trigger_ratio` 相乘得到触发线 | `100Mbps`/`1Gbps` 等 | 100Kbps – 1Tbps |
| `rx_limit` / `tx_limit` | 方向独立 | 触发后被限制到的速率（GCRA policer 的目标速率） | 同上 | 100Kbps – 1Tbps |
| `window` | 两方向共用 | 滑动观察窗口长度 | `30s`/`5m`/`1h` | > 0；窗口 > 3600 个采样时截断到 3600 个采样 |
| `trigger_ratio` | 两方向共用 | 触发线占阈值的百分比 | `80%` | 1% – 100% |
| `limit_duration` | 两方向共用 | 触发后限速持续多久，到期自动解除 | `30s`/`30m`/`1h` | > 0 |
| `burst` | 两方向共用 | 突发容量（字节）：桶类算法的桶容量、GCRA 的容忍量；窗口类算法不使用 | `1MiB`/`4MiB` 等（二进制） | ≤ 1GiB |
| `algorithm` | 两方向共用 | 限速算法，缺省 `gcra` | `token_bucket` / `leaky_bucket` / `fixed_window` / `sliding_window_counter` / `sliding_window_log` / `gcra` | 六选一 |
| `limit_window` | 两方向共用 | 窗口类算法的窗口长度；桶类与 GCRA 不使用 | `1s` – `60s` | 1s – 60s |

- 字段与算法的适用关系：桶类 / GCRA 需要 `burst`，窗口类需要 `limit_window`；
  不适用于所选算法的字段会被忽略（允许 override 从段策略继承而来）。
- 所有值一律整数，不接受浮点（`1.5Gbps` 会被拒绝，请写 `1500Mbps`）。
- 某方向只写了部分字段（例如有 `rx_threshold` 却没有 `rx_limit` 或 `window`）视为不完整策略，
  整份配置被拒绝加载并保持旧配置。
- 速率与突发的上下界是为了保证 eBPF 数据面的整数运算永不回绕，超出会被校验拒绝。

### 触发语义（何时进入限速）

对每个 `(IP, 方向)` 独立判定（RX 与 TX 互不影响，绝不用 RX+TX 合计）：

1. 触发线 = `threshold × trigger_ratio`（如 `1Gbps × 80% = 800Mbps`）。
2. daemon 每秒采样一次字节增量，维护该流的环形滑动窗口；
   窗口平均 = `窗口内总字节 × 8 ÷ 实际观察时长`。
3. **只有窗口观察满整个 `window` 之后**，且窗口平均 ≥ 触发线，才进入 LIMITED。
   瞬时尖峰、窗口未满都不会触发。
4. 计数回绕 / TAP 重建 / 策略刚挂上：按零差值处理，不会产生虚假触发。
5. 触发后立即向 eBPF 下发该 `(IP, 方向)` 的限速策略（所选算法 + `rx_limit`/`tx_limit`
   + `burst` 或 `limit_window`），并记录 `limited_since` / `limited_until`
   （`--ui` 详情页可见状态与剩余秒数）。

### 限速语义（触发之后发生什么）

- 所选算法在 TC eBPF 数据面执行 **policing**：符合速率的包放行，超出即**直接丢弃**
  （`TC_ACT_SHOT`）；不做队列整形（没有 HTB/TBF/netem）。被限流的 VM 表现为丢包重传，
  TCP 会收敛到限速值附近（真机实测 500+Mbit/s 的流被精确压在 ~202Mbit/s）。
- `burst`（桶类 / GCRA）是瞬时容忍量：空闲后重新来流量时，可以先放出约 `burst` 大小
  的数据再进入严格限速；窗口类算法则按 `limit_window` 内的字节配额判定。
- 持续 `limit_duration` 后**自动解除**：移除限速策略、清空该方向的观察窗口、回到 NORMAL，
  从零重新积累满窗口。若流量仍超触发线，会在满窗后再次触发（这是预期行为）。
- 限速只作用于触发的方向：RX 触发不影响 TX（反之亦然）。
- 监控计数点在限速点之前：`--ui` 里 LIMITED 流的窗口均值反映的是“需求量”，
  实际交付速率请看限速值或抓包。

### IP 级覆盖（单台机器例外）

IP 默认继承所属段的 `policy`。需要给个别机器不同待遇时，用
`[[ip_ranges.overrides]]`（必须写在它所属的 `[[ip_ranges]]` 块内部）：

```toml
  # 10.30.8.3 是付费升级用户：阈值和限速更高，窗口/时长/突发继承段策略
  [[ip_ranges.overrides]]
  ip = "10.30.8.3"
  rx_threshold = "2Gbps"
  rx_limit = "800Mbps"

  # 10.30.8.7 是问题机器：完全不参与限速（注意：覆盖里无法“关掉继承”，
  # 若要豁免单台，把它的段拆出来单独不设 policy，或把 threshold 调高）
```

- 合并规则：**字段级合并，写了的覆盖、没写的继承**（段 policy 为底，override 逐字段覆盖）。
- override 的 IP 必须落在所属段范围内，同一段内同一 IP 不可重复。
- 删除某个 override 后，该 IP 立即回落为继承段策略（热加载生效）。
- 段没有 `policy` 时，单独的 override 无法补齐共用字段，会被拒绝（不完整策略）。

### 热加载时修改限速参数的行为（运行中直接改，无需重启）

| 修改 | 行为 |
| --- | --- |
| LIMITED 中改 `rx_limit`/`tx_limit` | 立即按新速率限速，同时重置该方向算法运行状态（如 GCRA 的 TAT；旧速率的状态不污染新参数） |
| LIMITED 中改 `burst` / `limit_window` / `algorithm` | 立即生效 + 重置算法状态 |
| LIMITED 中改 `limit_duration` | 从原始 `limited_since` 重算 `limited_until`；若算出已过期则**立即解除** |
| 改 `window` | 该流的观察窗口清空、重新积累满窗（旧窗口数据不迁移） |
| 改 `threshold` / `trigger_ratio` | 保留当前窗口，下一次评估用新触发线 |
| 删除 policy / override | 立即移除对应限速、恢复 NORMAL；override 删除则回落继承 |
| 新增段 / 删除段 | 同步增删白名单与监控状态；删除段会清理其限速、算法状态和窗口 |
| 改 `collector.refresh_interval_ms` / `collector.map_max_entries` | **不支持热加载**：限速器窗口按整秒 tick 校准、eBPF map 容量启动时固定，校验拒绝并提示重启 |
| 新配置前缀数超容量 | 预检拒绝（不动任何 map）：新配置的 CIDR 前缀数 > 启动时定的 `MONITORED_IPS` 字典树容量时，明确要求重启调整。段再大也不逐地址枚举；`TRAFFIC`/限速类 map 按真实出现的流动态占用，满时逐流降级（不计数/不限速，放行） |
| 改 `network.bridge` | **不支持热加载**，校验直接拒绝，需要重启进程 |
| 任何非法配置 | 整份拒绝：保持上一次成功配置（last-known-good），不中断监控与限速，`--ui` 顶栏显示 FAILED 与原因 |

### 参数设置建议与完整示例

- **先观察再设阈值**：先不设 policy 运行一段时间，用 `--ui` 看各段的常态流量，
  把 `threshold` 设在“正常水位的上限”，`trigger_ratio` 用 80% 留余量。
- `limit` 通常设在 `threshold × trigger_ratio` 以下（触发线附近或更低），
  否则限了也看不出效果。
- `window` 越短响应越快、越容易误伤突发业务；越长越稳。通用起点 `5m`。
- `limit_duration` 是“处罚时长”，不是整形时长；想长期压住就把时长设长，
  或配合告警人工处理。
- `burst` 给 1–4MiB 即可：太小会误伤正常突发（如 HTTP 请求头、心跳），太大则限速手感变软。
- 验证效果：`--ui` 详情页看状态/剩余时间，配合宿主机上对该机器 TAP 抓包测交付速率。

一个混合示例（段级策略 + 单 IP 例外 + 纯监控段）：

```toml
[[ip_ranges]]
name = "Standard"
range = "10.30.8.1-10.30.8.64"

  [ip_ranges.policy]
  rx_threshold = "800Mbps"
  tx_threshold = "400Mbps"
  window = "5m"
  trigger_ratio = "80%"
  rx_limit = "400Mbps"
  tx_limit = "200Mbps"
  limit_duration = "30m"
  burst = "4MiB"

  # 单台高配机器放宽
  [[ip_ranges.overrides]]
  ip = "10.30.8.10"
  rx_threshold = "2Gbps"
  tx_threshold = "1Gbps"
  rx_limit = "1Gbps"
  tx_limit = "500Mbps"

[[ip_ranges]]
name = "Internal"
range = "10.30.9.1-10.30.9.32"
# 不写 policy：只监控，不限速
```

## 查看与解除限速

### 如何查看当前是否有限速

按可信度从高到低，三种方式互相印证：

1. **`--ui` 界面**（最快）：
   - 总览页每个段都有 `Limited` 列：`0` 表示该段没有任何流处于限速；> 0 即有限速中的流。
   - 按回车进详情页，`状态` 列逐流显示 `NORMAL` / `LIMITED`，LIMITED 还会显示剩余秒数。
     详情页只列出**本次启动以来出现过流量**的 IP（段不再逐地址展开）；段的
     `IPs` 数即已观测地址数。
2. **日志**：触发与解除都会落日志，直接查：

   ```bash
   journalctl -u vm-bandwidth-monitor | grep -iE "limited|trigger|expire"
   ```

3. **eBPF 数据面实证**（最权威，需 `bpftool`）：数据面是否真的在丢包只取决于两张 map，
   两者都是 `[]`（空）即**没有任何生效中的限速**：

   ```bash
   apt-get install -y bpftool            # 若未安装（仅诊断用，不影响运行中的 daemon）
   bpftool map dump name LIMIT_POLICIES   # 生效中的限速策略；[] = 无
   bpftool map dump name LIMIT_STATE      # 算法运行状态（TAT/令牌/窗口等）；[] = 无
   bpftool map dump name SWL_LOG          # 滑动窗口日志环（仅该算法在用时非空）
   ```

   配置里没有 `[ip_ranges.policy]` 时，这两张 map 必然为空：限速器只给带策略的流下发，
   策略不存在就不可能触发（配置可用 `grep -E "(policy|limit|threshold|burst)" config.toml` 快速确认）。

### 如何解除限速

限速的写入方只有限速器，解除即“移除策略/状态”，全部热生效、无需重启：

| 想解除的范围 | 做法 |
| --- | --- |
| 某段的全部限速 | 删掉该段的 `[ip_ranges.policy]` 块，保存。热加载后该段所有 LIMITED 流立即恢复 NORMAL，限速策略与状态一并移除 |
| 单台机器的限速 | 给该 IP 加一条 `[[ip_ranges.overrides]]`，把 `rx_limit`/`tx_limit` 设成极高值（如 `1Tbps`，校验上限）；或把该段拆出来不设 policy；无法用 override “删除”继承来的策略 |
| 缩短剩余时长 | 把 `limit_duration` 改小：`limited_until` 从原始 `limited_since` 重算，算出已过期则**立即解除** |
| 全部清零重来 | `systemctl restart vm-bandwidth-monitor`：所有窗口、限速状态清空，从基线重新观察；配置本身不变，满窗后仍可能再次触发（治标手段，不是禁用） |
| 永久禁用限速 | 配置中不保留任何 `[ip_ranges.policy]`（默认 `config.toml` 就是这种状态） |
| 等待自动解除 | 什么都不做：`limit_duration` 到期自动恢复并重新观察 |

注意：解除是即时生效的（下一个包就不再按旧策略判），但解除后窗口会重新积累，
若流量仍超触发线，满窗后会再次触发——这是预期行为，不是残留故障。
解除后想确认干净，用上面「查看」的第 3 条验证两张 map 均为 `[]` 即可。


## 限速（数据面实现）

- 六种算法统一抽象：策略带算法标签写入 `LIMIT_POLICIES`，TC eBPF 数据面每包按
  标签分发到对应判定逻辑；conforming 放行，non-conforming 丢弃（`TC_ACT_SHOT`）。
  不引入 HTB/TBF/IFB/netem，不做队列整形。
- 运行状态统一存 `LIMIT_STATE`（共享、非 per-CPU），每流三个通用 `u64` 字段，
  各算法含义不同：令牌桶 = 令牌数/上次回填时间，漏桶 = 水位/上次漏出时间，
  固定窗口 = 已用字节/窗口起点，滑动窗口计数器 = 前窗字节/当前窗字节/窗口起点，
  GCRA = TAT。滑动窗口日志单独使用 `SWL_LOG`（定长 1024 条的时间戳+长度环）。
- GCRA 判定：`increment = len×8×1e9/rate`（可变包长按比特率、整数运算、防溢出）；
  `tolerance = burst×8×1e9/rate`；`candidate = max(now, TAT) + increment`；
  `candidate ≤ now + tolerance` 则放行并更新 TAT，否则丢弃。首包初始化即放行。
- 限速 key 只含 `(IPv4, 方向)`，不含 ifindex——同一 IP+方向在**所有 CPU、所有 TAP**
  上共享同一速率额度。状态用 `bpf_spin_lock` 防止多 CPU 并发丢失更新；时间戳在
  加锁前取得，锁内不做任何 helper 调用，所有路径都释放锁。
- 策略全部由用户态决定：eBPF 不知道 IP 段、继承、窗口、百分比、时长、热加载，只认
  `LIMIT_POLICIES` 里当前 `(IP, 方向)` 是否启用、什么算法、什么参数。
- 进入/离开 LIMITED、安装/移除策略、更新速率、切换算法均记录日志；任何 map/校验
  异常都 fail-open（不影响 VM 网络）。

## 热加载

- 监听配置文件所在目录（兼容编辑器 atomic rename），300ms 去抖：一次正常保存 ≈ 一次
  reload。`SIGHUP` 走同一套管线。
- 事务式：读取 → 完整解析 → 完整校验 → 限速器生成**纯变更计划**（不改自身状态）
  → 按序执行全部 map 操作：白名单前缀新增 → 解除限速（先解除武装再清状态）→
  安装限速（先解除旧武装、清异类状态、写新状态，策略**最后**写入，写入即生效
  标志——任何时刻"已武装策略 ⇒ 对应状态已存在"）→ 白名单前缀移除 →
  全部成功才提交限速器状态、切换配置并递增 `generation`；任一 map 操作失败则
  逆向回滚已执行部分并保持上一份配置。回滚同样是状态先于策略；若回滚自身也
  失败，数据面可能与当前配置不一致——每条受影响流的最终状态以逐步
  `RollbackFailure` 错误日志为准（可能是旧策略重新武装、新限速仍然生效、或
  解除武装并留下有界孤儿状态），硬不变量“已武装策略 ⇒ 对应状态存在”保持。
  日志按错误级输出并置位 `dataplane_degraded`（IPC/UI 可见 `DATAPLANE
  DEGRADED` 与失败计数），绝不静默吞掉。成功后立即重采集一次，IPC 快照在新
  配置下重建，不存在旧快照×新配置的混合窗口。
- 只能重启、不能热载的字段：`network.bridge`、`collector.refresh_interval_ms`、
  `collector.map_max_entries`、`collector.swl_map_max_entries`（map 容量与窗口
  标定在启动时固定）；热载修改会被拒绝并提示重启。
- 校验失败：拒绝该次 reload，完整保留上一次成功配置，不清空、不中断、不退出，
  `--ui` 顶栏显示 `FAILED` 及原因，`generation` 不变。
- 文件监听器（inotify）报错不会静默吞掉：记录日志、累计计数，经 IPC 暴露
  （`config_watcher_healthy` / `config_watcher_errors_total` / `config_watcher_last_error`），
  `--ui` 顶栏在不健康时显示 `WATCHER UNHEALTHY`（提示热加载可能已失效）。
- LIMITED 状态下修改：`rate`/`burst`/`limit_window`/`algorithm` 变更立即生效并
  重置该方向限速状态；
  `limit_duration` 变更按原 `limited_since` 重算 `limited_until`（可能立即解除）；
  删除限速配置立即恢复 NORMAL；`window` 变更清空窗口重新积累。
- 新增/删除 IP 段同步增删 `MONITORED_IPS` 的 CIDR 前缀（段的差分以分解后的前缀
  集计算），并清理对应的窗口/限速/计数器状态。

## 界面（--ui）

启动后进入 **IP Range Overview**：每个段的名称、范围、实时 RX/TX、累计 RX/TX、
IP 数（本次启动以来出现过流量的地址数）、Limited 数；顶栏显示 bridge、TAP 数、
`Config generation`、最近一次 reload 的时间与状态（失败时附原因）。选中段按 `Enter`
进入 **IP Range Detail**：段内每个已观测 IP 的实时速率、窗口平均、有效策略（阈值/
限速）、`NORMAL`/`LIMITED` 状态与剩余限速时间。

| 页面 | 按键 | 功能 |
| --- | --- | --- |
| 首页 | `↑`/`↓` | 选择 IP 段 |
| 首页 | `Enter` | 进入详情 |
| 首页 | `t` | 打开选中段的范围趋势 |
| 首页 | `r` | 立即刷新 |
| 首页 | `h` | 帮助 |
| 首页/详情 | `q` | 退出 |
| 详情 | `↑`/`↓` | 选择 IP |
| 详情 | `s` | 切换排序（IP → RX → TX → RX+TX） |
| 详情 | `r` | 立即刷新 |
| 详情 | `Enter` | 打开选中 IP 的历史趋势 |
| 详情 | `t` | 打开整个段的范围趋势 |
| 详情 | `Esc` | 返回 |
| 趋势 | `←`/`→` 或 `1`-`4` | 切换窗口（1h / 24h / 7d / 30d） |
| 趋势 | `b` / `p` | 带宽 / 发包量 |
| 趋势 | `Esc` | 返回来源页面 |

界面列宽随终端宽度自适应：窄终端自动收敛为精简列集，不再叠字。首页末尾有全段
合计行（`Σ All ranges`，含 IP 总数），详情页头部显示该段累计 RX/TX 总量（自本次启动起）。

| 页面 | 档位 | 触发宽度 | 列集 |
| --- | --- | --- | --- |
| 首页 | Wide | ≥105 列 | 名称、IP 范围、RX、TX、RX/TX 累计、IP 数、Limited |
| 首页 | Mid | ≥66 列 | 名称、IP 范围、RX、TX、Limited |
| 首页 | Min | 更窄 | 名称+范围（两行叠一格）、RX、TX、Limited |
| 详情 | Wide | ≥149 列 | 全部 13 列（含 Dropped、窗口平均、分方向限速与状态、剩余时间） |
| 详情 | Mid | ≥101 列 | IPv4、RX/TX、累计、限速、状态、剩余时间 |
| 详情 | Min | 更窄 | IPv4、RX、TX、状态 |

趋势屏支持两种对象：**单 IP 趋势**（详情页 `Enter`）与**范围趋势**（首页/详情页
`t`，段内全部 IP 聚合），两者共享窗口切换与带宽/发包量开关。

## 历史趋势（VictoriaMetrics）

```bash
cd dist && docker compose up -d     # 单节点，监听 127.0.0.1:8428，保留 35 天
```

URL 安全策略：本机回环可用 `http://`；远程必须 `https://`（内置 rustls）；
远程明文 `http://` 默认拒绝，除非显式 `allow_insecure_http = true`（承担客户
带宽数据不加密、无鉴权出网的风险）。

然后在 `config.toml` 启用：

```toml
[metrics]
enabled = true
url = "http://127.0.0.1:8428"
push_interval_secs = 60
```

`[metrics]` 参与热加载：改动在文件监听触发后的下一个推送周期生效。数据模型：每 IP 四条累计计数器（`vmbw_{rx,tx}_{bytes,packets}_total`，
标签 `ip`/`range`），趋势屏用 `rate()` 查询，daemon 重启造成的计数器归零由
`rate()` 按标准 counter reset 处理。被限速的流另有八条裁决计数器（`vmbw_policer_{rx,tx}_{passed,dropped}_{bytes,packets}_total`）：
TRAFFIC 记的是限速前的流量需求，这组才是实际放行/丢弃量。范围趋势用
`sum(rate(...{range="段名"}))` 聚合段内全部 IP；单 IP 与范围的 RX/TX 两个方向查询并行发出。

另有四条进程级运维累计计数器（固定标签 `instance="process"`，基数恒定）：
`vmbw_tap_attach_failures_total`（TAP 挂载失败）、`vmbw_metrics_push_{successes,failures,skipped}_total`（推送成功/失败/因上一推送未结束而跳过）。
注意 VM 侧的成功序列天然滞后一轮：一次推送在自身完成前无法计入自己的成功，
payload 里携带的是本次推送开始前的累计值；失败与跳过在渲染时即为当前值。
（滞后只影响导出到 VictoriaMetrics 的序列；IPC `Status` 直接读进程内原子计数，
查询时即为当前值。）

## 实现要点

- **单一 eBPF 对象，挂载到所有 TAP**：对象只加载一次（验证器只跑一遍），
  `tc_ingress`/`tc_egress` 直接从 `__sk_buff` 上下文读取 ifindex，同一对程序以
  TCX/netlink 链接挂到每个 TAP；七份 map（LPM 字典树白名单、IPv4/IPv6 计数、限速策略、
  限速状态、滑窗日志、限速裁决统计）天然共享，不 pin，随 daemon 生命周期存在
  （白名单为普通 map，其余为 BTF 定义）。
- **VLAN/QinQ**：最多两层 802.1Q/802.1ad 标签（编译期上限，非数据驱动循环）被
  剥离后按内层 IPv4/IPv6 进入同一套计数与限速；更深层标签、截断标签与非 IP
  载荷一律 fail-open 放行（不计不丢）。
- **IPv6 按 TAP 聚合**：`TRAFFIC6` 的 key 是 ifindex 而非（ifindex, 地址），
  map 基数被限制在 TAP 数量——单台 VM 轮换 IPv6 隐私地址不会耗尽计数 map。
- 挂载/卸载由 `AttachManager` 负责：丢弃某个链接即移除**且仅移除**本程序创建的
  TC filter；不动 `fq_codel`/`noqueue`，不清理其他程序的 filter。
- qdisc 生命周期（v0.6.4 起）：
  - **Linux ≥6.6 默认走 TCX**（`bpf_link_create`），先直接 attach，不需要任何
    qdisc，退出后接口上不会遗留本程序创建的 `clsact`。
  - 旧内核回退传统 netlink TC：仅当首次 attach 以 ENOENT 证明挂钩缺少父 qdisc 时，
    才创建 `clsact` 并重试一次；已存在的 `clsact` 一律复用（EEXIST），不替换、
    不删除。其他错误（权限、接口不存在等）如实上抛，不会被当成“已存在”。
  - ingress 成功而 egress 失败时回滚 ingress 链接；若是遗留 `ingress` 独占 qdisc
    导致 egress 无处可挂，给出明确的冲突诊断。
  - attach 失败按指数退避重试（5s 起、上限 5 分钟）并计数入日志，持久冲突不再每 5 秒刷屏。
  - **程序永不删除无法确认归属的共享 qdisc**：本程序自建的 `clsact` 在卸载时也仅“保留并记录”，
    因为 aya 0.14 无法安全证明没有其他工具的 filter 共用它；根 qdisc 永不触碰。
  - 历史版本（< v0.6.4）遗留的空 `clsact` 需一次性手工清理（前提：两个 filter 查询均为空，
    且 vm-bandwidth-monitor 已停止）：
    ```bash
    DEV=<tap>
    tc filter show dev "$DEV" ingress
    tc filter show dev "$DEV" egress
    tc qdisc del dev "$DEV" clsact
    ```
- 计数为单调累计值，用户态按相邻采样差值计算速率；计数回绕/复位或 TAP 重建时该周期
  记 0，绝不产生负带宽或虚假触发。
- 计数键闲置回收：`(ifindex, IP)` 计数连续约 5 分钟（默认 1s 采样 × 300 刻）无变化即从
  `TRAFFIC`/`TRAFFIC6` 淘汰（IPv4 与 IPv6 同规则，IPv6 地址轮换/隐私地址不再泄漏条目）；
  有流量回来时数据面会在首个包重建条目（累计计数复位对用户态差值与 `rate()` 均安全）。
  这同时把用户态每 IP 状态裁剪到“计数 map 里仍有键”的 IP，长时运行不再单调增长。
- 单一 "engine" 任务持有全部可变状态（map、TAP、collector、limiter），IPC/监听/信号
  通过有界 channel 与其通信——单写者，无共享可变锁。引擎循环内的阻塞段（配置读取、
  map 迭代、TAP 扫描）以 `block_in_place` 包裹，IPC 任务可迁往其他 worker，不被阻塞。
- HTTP 出站统一走 reqwest（http-only，5s 超时，响应体 1MiB 上限）。指标推送在引擎上完成渲染后，
  仅网络发送放入派生任务，端点卡住最多卡住它自己、不再阻塞采样 tick；同一时刻至多一个推送在途，
  上一推未回则本次跳过、下刻用新累计值重试。推送客户端不复用连接（每分钟一次、本地调用，
  避免与 VictoriaMetrics 较短的 keep-alive 超时竞争）。`--ui` 趋势抓取跑在单 worker 运行时上经通道回传结果，
  界面在抓取期间保持刷新。
- 滑动窗口是固定大小环形缓冲（每 (IP,方向) 一个、仅对有策略的 IP 分配），增删均摊
  O(1)，删除 IP/段即释放。
- `/run/vm-bandwidth-monitor.lock` 文件锁防止双开；启动清理上次遗留的 pin，退出再清理。
  IPC socket 以 0600 创建（只读状态含每客户带宽，仅属主可读）。

## 已知边界（v2）

- IPv6 只聚合计数（首页/趋势可见），不限速、无按 IP 拆分；ARP/非 IP 流量不统计；不解析端口、连接、payload。
- 超过 65535 字节的报文（如 GSO 聚合帧）目前不被限速器处理（放行且计入
  `oversized` 观测为待验证项，见 `docs/kernel-validation.md`），该行为是否构成
  绕过取决于宿主是否把超大帧递交给 TAP 的 TC 挂钩——尚未在真实内核裁决，保留
  为已知限制。
- `map_max_entries` 耗尽时新的计数键不再计数、新的限速策略无法安装（数据包仍放行，
  记日志）。
- 累计流量自本次启动起计（每次启动重建 map）。
- 限速是 policing：超限直接丢包，不做缓冲/整形；对被限流方表现为丢包重传。
  TRAFFIC 计数发生在限速之前（流量需求）；实际放行/丢弃由 `POLICER_STATS` 记录，
  仅对有生效策略的流建条目，展示于详情页（Wide 档 Dropped 列、页头丢弃合计、首页 Σ 行）。
- 窗口采样粒度 = `refresh_interval_ms`；窗口长度超过 `3600 × 采样粒度` 时会截断到该
  上限（极长窗口场景）。
