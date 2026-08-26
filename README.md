# vm-bandwidth-monitor

[![CI](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml)

实时统计 Linux Bridge（`br0`）下虚拟机按 IPv4 地址划分的网络带宽，并可对 IP 段 / 单个
IP 做 **GCRA 限速**。eBPF (TC/SchedClassifier, Aya) 采集与执行，长期运行 daemon +
只读 `--ui` 终端界面，`config.toml` 热加载，无数据库、无 HTTP 服务、无 REST/gRPC。

- 只统计 `config.toml` 配置的 `开始IP-结束IP` 地址段内的 IPv4，其余一律放行不计数。
- 每个 TAP 接口挂载 TC ingress（VM TX，按源 IP）与 TC egress（VM RX，按目标 IP）。
- TAP 识别不依赖接口名（支持纯数字接口名），按 `tun_flags` 判定；周期重扫，
  新增/删除 VM 无需重启。
- **限速**：每个 `(IP, 方向)` 维护滑动窗口平均，达到 `threshold × trigger_ratio`
  后进入 LIMITED，向 eBPF 下发 GCRA 策略；持续 `limit_duration` 后自动恢复。
- **热加载**：修改 `config.toml` 自动生效（文件监听 + `SIGHUP`），先完整校验再一次性
  应用；非法配置被拒绝且保持上一次成功配置（last-known-good）。
- eBPF 数据面只做观察计数与 GCRA policing，任何异常路径一律放行（fail-open）。

## 工作区结构

| crate | 说明 |
| --- | --- |
| `vm-bandwidth-common` | eBPF 与用户态共享的 `#[repr(C)]` 类型（`TrafficKey/Value`、`GcraKey/Policy/State`、方向常量） |
| `vm-bandwidth-ebpf` | TC classifier：计数 + GCRA policer（no_std，nightly 编译） |
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

启动流程：读取并完整校验配置 → 提升文件描述符上限 → 生成 IP 白名单写入
`MONITORED_IPS` → 发现 br0 下的 TAP 并挂载 TC → 每秒采样计算带宽、驱动滑动窗口与
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
map_max_entries = 8192            # TRAFFIC / LIMIT_POLICIES / GCRA_STATE 容量

[display]
default_sort = "ip"               # --ui 详情页初始排序: ip | rx | tx | total

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

**不写 `[ip_ranges.policy]` = 该段只监控、不限速。** 想关闭限速，把 policy 块删掉保存即可，
热加载会立即移除该段所有流的限速并恢复 NORMAL。

### 字段说明

| 字段 | 归属 | 含义 | 单位 | 约束 |
| --- | --- | --- | --- | --- |
| `rx_threshold` / `tx_threshold` | 方向独立 | 阈值，与 `trigger_ratio` 相乘得到触发线 | `100Mbps`/`1Gbps` 等 | 100Kbps – 1Tbps |
| `rx_limit` / `tx_limit` | 方向独立 | 触发后被限制到的速率（GCRA policer 的目标速率） | 同上 | 100Kbps – 1Tbps |
| `window` | 两方向共用 | 滑动观察窗口长度 | `30s`/`5m`/`1h` | > 0；窗口 > 3600 个采样时截断到 3600 个采样 |
| `trigger_ratio` | 两方向共用 | 触发线占阈值的百分比 | `80%` | 1% – 100% |
| `limit_duration` | 两方向共用 | 触发后限速持续多久，到期自动解除 | `30s`/`30m`/`1h` | > 0 |
| `burst` | 两方向共用 | GCRA 突发容忍量（字节） | `1MiB`/`4MiB` 等（二进制） | ≤ 1GiB |

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
5. 触发后立即向 eBPF 下发该 `(IP, 方向)` 的 GCRA 策略（`rx_limit`/`tx_limit` + `burst`），
   并记录 `limited_since` / `limited_until`（`--ui` 详情页可见状态与剩余秒数）。

### 限速语义（触发之后发生什么）

- GCRA 在 TC eBPF 数据面执行 **policing**：符合速率的包放行，超出即**直接丢弃**
  （`TC_ACT_SHOT`）；不做队列整形（没有 HTB/TBF/netem）。被限流的 VM 表现为丢包重传，
  TCP 会收敛到限速值附近（真机实测 500+Mbit/s 的流被精确压在 ~202Mbit/s）。
- `burst` 是瞬时容忍量：空闲后重新来流量时，可以先放出约 `burst` 大小的数据再进入严格限速。
- 持续 `limit_duration` 后**自动解除**：移除 GCRA 策略、清空该方向的观察窗口、回到 NORMAL，
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
| LIMITED 中改 `rx_limit`/`tx_limit` | 立即按新速率限速，同时重置该方向 GCRA 的 TAT（旧速率的状态不污染新参数） |
| LIMITED 中改 `burst` | 立即生效 + 重置 GCRA 状态 |
| LIMITED 中改 `limit_duration` | 从原始 `limited_since` 重算 `limited_until`；若算出已过期则**立即解除** |
| 改 `window` | 该流的观察窗口清空、重新积累满窗（旧窗口数据不迁移） |
| 改 `threshold` / `trigger_ratio` | 保留当前窗口，下一次评估用新触发线 |
| 删除 policy / override | 立即移除对应限速、恢复 NORMAL；override 删除则回落继承 |
| 新增段 / 删除段 | 同步增删白名单与监控状态；删除段会清理其限速、GCRA 状态和窗口 |
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

## 限速（GCRA）

- 唯一限速算法是 GCRA，TC eBPF 内做 policing：conforming 放行，non-conforming 丢弃
  （`TC_ACT_SHOT`）。不引入 HTB/TBF/IFB/netem，不做队列整形。
- 每个 `(IP, 方向)` 维护 TAT（Theoretical Arrival Time）。`increment = len×8×1e9/rate`
  （可变包长按比特率、整数运算、防溢出）；`tolerance = burst×8×1e9/rate`。
  `candidate = max(now, TAT) + increment`；`candidate ≤ now + tolerance` 则放行并更新
  TAT，否则丢弃。首包初始化即放行。
- GCRA key 只含 `(IPv4, 方向)`，不含 ifindex——同一 IP+方向在**所有 CPU、所有 TAP**
  上共享同一速率额度。状态存于共享 `GCRA_STATE`（非 per-CPU），用 `bpf_spin_lock`
  防止多 CPU 并发丢失更新；时间戳在加锁前取得，所有路径都释放锁。
- 策略全部由用户态决定：eBPF 不知道 IP 段、继承、窗口、百分比、时长、热加载，只认
  `LIMIT_POLICIES` 里当前 `(IP, 方向)` 是否启用及其 `rate`/`burst`。
- 进入/离开 LIMITED、安装/移除策略、更新速率均记录日志；任何 map/校验异常都
  fail-open（不影响 VM 网络）。

## 热加载

- 监听配置文件所在目录（兼容编辑器 atomic rename），300ms 去抖：一次正常保存 ≈ 一次
  reload。`SIGHUP` 走同一套管线。
- 事务式：读取 → 完整解析 → 完整校验 → 生成新 EffectiveConfig → 与现有配置做
  added/removed/changed 差分 → 一次性按安全顺序应用（新增先写白名单，删除先清限速再
  删白名单）→ 切换 active config 并递增 `config_generation`。
- 校验失败：拒绝该次 reload，完整保留上一次成功配置，不清空、不中断、不退出，
  `--ui` 顶栏显示 `FAILED` 及原因，`generation` 不变。
- LIMITED 状态下修改：`rate`/`burst` 变更立即生效并重置该方向 GCRA 状态；
  `limit_duration` 变更按原 `limited_since` 重算 `limited_until`（可能立即解除）；
  删除限速配置立即恢复 NORMAL；`window` 变更清空窗口重新积累。
- 新增/删除 IP 段同步增删 `MONITORED_IPS`，并清理对应的窗口/限速/计数器状态。

## 界面（--ui）

启动后进入 **IP Range Overview**：每个段的名称、范围、实时 RX/TX、累计 RX/TX、IP 数、
Limited 数；顶栏显示 bridge、TAP 数、`Config generation`、最近一次 reload 的时间与
状态（失败时附原因）。选中段按 `Enter` 进入 **IP Range Detail**：段内每一个 IP 的
实时速率、窗口平均、有效策略（阈值/限速）、`NORMAL`/`LIMITED` 状态与剩余限速时间。

| 页面 | 按键 | 功能 |
| --- | --- | --- |
| 首页 | `↑`/`↓` | 选择 IP 段 |
| 首页 | `Enter` | 进入详情 |
| 首页 | `r` | 立即刷新 |
| 首页 | `h` | 帮助 |
| 首页/详情 | `q` | 退出 |
| 详情 | `↑`/`↓` | 选择 IP |
| 详情 | `s` | 切换排序（IP → RX → TX → RX+TX） |
| 详情 | `r` | 立即刷新 |
| 详情 | `Esc` | 返回 |

## 实现要点

- **单一 eBPF 对象，挂载到所有 TAP**：对象只加载一次（验证器只跑一遍），
  `tc_ingress`/`tc_egress` 直接从 `__sk_buff` 上下文读取 ifindex，同一对程序以
  TCX/netlink 链接挂到每个 TAP；四份 map（白名单、计数、限速策略、GCRA 状态）
  全部为 BTF 定义、天然共享，不 pin，随 daemon 生命周期存在。
- 挂载/卸载由 `AttachManager` 负责：丢弃某个链接即移除**且仅移除**本程序创建的
  TC filter；不动 `fq_codel`/`noqueue`，不清理其他程序的 filter。
- 计数为单调累计值，用户态按相邻采样差值计算速率；计数回绕/复位或 TAP 重建时该周期
  记 0，绝不产生负带宽或虚假触发。
- 单一 "engine" 任务持有全部可变状态（map、TAP、collector、limiter），IPC/监听/信号
  通过有界 channel 与其通信——单写者，无共享可变锁。
- 滑动窗口是固定大小环形缓冲（每 (IP,方向) 一个、仅对有策略的 IP 分配），增删均摊
  O(1)，删除 IP/段即释放。
- `/run/vm-bandwidth-monitor.lock` 文件锁防止双开；启动清理上次遗留的 pin，退出再清理。

## 已知边界（v2）

- 不统计 IPv6/ARP/非 IP 流量；不解析端口、连接、payload。
- `map_max_entries` 耗尽时新的计数键不再计数、新的限速策略无法安装（数据包仍放行，
  记日志）。
- 累计流量自本次启动起计（每次启动重建 map）。
- GCRA 是 policing：超限直接丢包，不做缓冲/整形；对被限流方表现为丢包重传。
- 窗口采样粒度 = `refresh_interval_ms`；窗口长度超过 `3600 × 采样粒度` 时会截断到该
  上限（极长窗口场景）。
