# vm-bandwidth-monitor

[![CI](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml)

[English](README.md) | **简体中文** | [日本語](README.ja-JP.md)

实时统计 Linux 网桥（如 `br0`）下虚拟机按 IPv4 地址划分的网络带宽，并可对 IP 段 /
单个 IP 做**限速**。eBPF (TC/SchedClassifier, Aya) 数据面负责计数与限速执行，长期运行的
daemon 驱动观察窗口与限速状态机，只读终端界面 `--ui` 展示实时数据与历史趋势，
`config.toml` 热加载。默认无数据库、无 HTTP 服务；可选把累计流量推送到
VictoriaMetrics 查看任意 IP 的历史趋势。

- 只统计 `config.toml` 配置的 `开始IP-结束IP` 地址段，其余一律放行不计数。段被分解为
  最少的 CIDR 前缀写入 eBPF **LPM 字典树**（`MONITORED_IPS`），段大小不再逐地址枚举、
  与 map 占用解耦。IPv6 另行聚合统计：只计数、不限速、无按 IP 拆分。
- 每个 TAP 接口挂载 TC ingress（VM TX，按源 IP）与 TC egress（VM RX，按目标 IP）。
  TAP 识别按 `tun_flags` 判定、不依赖接口名；周期重扫，新增/删除 VM 无需重启。
- **限速**：每个 `(IP, 方向)` 维护滚动平均窗口，越过 `threshold × trigger_ratio`
  后向 eBPF 下发所选算法的限速策略，持续 `limit_duration` 后自动恢复。
- **热加载**：修改 `config.toml` 事务式自动生效（文件监听 + `SIGHUP`），任何失败
  回滚到上一份成功配置。
- 数据面只做观察计数与限速 policing，任何异常路径一律放行（fail-open）。

## 特性

- 按 IP 的实时与累计 RX/TX 字节数/包数，1 秒采样
- 六种可按段选择的限速算法（默认 GCRA）——见 [examples/](examples/)
- 观测触发式执法：NORMAL/LIMITED 生命周期，到期自动恢复
- 单 IP 策略覆盖，字段级继承
- 事务式热加载；非法配置绝不打断监控
- 只读终端界面：段总览、按 IP 详情、1h/24h/7d/30d 趋势
- 可选 VictoriaMetrics 推送（累计计数器，标准 `rate()` 查询）
- 只读 Unix socket IPC；数据面单一所有者
- 优雅退出：仅移除本程序创建的 TC 挂载，清理 map pin
- 全程 fail-open：本程序的任何异常都不会破坏 VM 网络

## 工作区结构

| crate | 说明 |
| --- | --- |
| `vm-bandwidth-common` | eBPF 与用户态共享的 `#[repr(C)]` 类型（流量/限速键、SWL 环、算法常量） |
| `vm-bandwidth-ebpf` | TC classifier：计数 + 多算法 policer（no_std，nightly 编译） |
| `vm-bandwidth-core` | 纯逻辑：单位解析、配置校验、策略继承、窗口、限速状态机、IPC 类型。不依赖 aya，任意平台可单测 |
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
> 若默认 `nightly` 的 LLVM 比本机 bpf-linker 新（报 `Invalid record`），安装一个
> LLVM 版本匹配的旧 nightly，然后：`VM_BW_EBPF_TOOLCHAIN=nightly-<日期> cargo build --release`。

产物：`target/release/vm-bandwidth-monitor`。

> 开发机技巧：`AYA_BUILD_SKIP=1 cargo test` 可跳过 eBPF 编译；`vm-bandwidth-core`
> 的纯逻辑单测不需要 Linux，任意平台可跑。

## 快速开始

需要 root（CAP_BPF + CAP_NET_ADMIN），且 `/sys/fs/bpf` 已挂载（通常默认挂载）。

```bash
# daemon（生产形态：由 systemd 管理）
sudo ./target/release/vm-bandwidth-monitor --config config.toml

# 只读终端界面，连接正在运行的 daemon
./target/release/vm-bandwidth-monitor --ui
```

启动流程：读取并完整校验配置 → 提升文件描述符上限 → 把各段分解为 CIDR 前缀写入
`MONITORED_IPS` → 发现网桥下的 TAP 并挂载 TC → 每秒采样、驱动窗口与限速器 →
在 `/run/vm-bandwidth-monitor.sock` 提供只读 IPC → 监听配置变化。

`SIGINT`/`SIGTERM` 干净退出（仅移除本程序创建的 TC 挂载、删除 map pin 与 socket）；
`SIGHUP` 触发一次配置 reload。`--ui` 客户端绝不重新加载 eBPF、不创建 map、不挂载
TC——数据面只有一个所有者（daemon）。

## 配置（config.toml）

```toml
[network]
bridge = "br0"

[collector]
refresh_interval_ms = 1000        # 采样周期，也是窗口的采样粒度
interface_scan_interval_secs = 5  # TAP 重扫周期
map_max_entries = 8192            # TRAFFIC / LIMIT_POLICIES / LIMIT_STATE / SWL_LOG 容量

[display]
default_sort = "ip"               # --ui 详情页初始排序: ip | rx | tx | total
# show_idle_ips = true            # 枚举段内全部 IP（含零流量的 0 值行）。默认关闭；
                                  # 超过 4096 个地址的段即使开启也不枚举

[metrics]                         # 可选：历史趋势（VictoriaMetrics）
enabled = false
url = "http://127.0.0.1:8428"
push_interval_secs = 60

[[ip_ranges]]
name = "VM-Network-1"
range = "10.30.8.1-10.30.8.16"

  [ip_ranges.policy]              # 不写此块 = 只监控不限速
  rx_threshold = "1Gbps"
  tx_threshold = "500Mbps"
  window = "5m"
  trigger_ratio = "80%"
  rx_limit = "500Mbps"
  tx_limit = "200Mbps"
  limit_duration = "30m"
  burst = "4MiB"

  [[ip_ranges.overrides]]         # 单 IP 例外，字段级合并
  ip = "10.30.8.3"
  rx_threshold = "2Gbps"
  rx_limit = "800Mbps"
```

规则：

- 段只支持 `开始IP-结束IP`（不支持 CIDR、通配符、反向范围），段之间不允许重叠。
- `policy` 可选：不写即只监控。`rx_threshold/tx_threshold`、`rx_limit/tx_limit`
  按方向独立；`window`、`trigger_ratio`、`limit_duration`、`burst` 两方向共用。
  某方向只配置部分字段（不完整）会被拒绝。
- 单位：速率 `100Mbps`/`1Gbps`（1000 进制）；时长 `5m`/`30m`/`1h`；百分比 `80%`；
  突发 `4MiB`（二进制）。一律整数，不接受浮点。
- override 的 IP 必须落在所属段内且同一段内不可重复；未写字段继承段策略。
- `[metrics]`（可选，默认关闭）：每 `push_interval_secs`（5–3600）秒推送一次累计
  计数器。本机回环可用 `http://`；远程必须 `https://`，除非显式
  `allow_insecure_http = true`。

## 限速

限速器是**观测触发式**的：每个 `(IP, 方向)` 独立判定（RX 与 TX 绝不相加）。

1. 触发线 = `threshold × trigger_ratio`（如 `1Gbps × 80% = 800Mbps`）。
2. daemon 每秒采样字节增量维护滚动窗口；窗口平均 = `窗口内总字节 × 8 ÷ 实际观察时长`。
3. **只有窗口观察满整个 `window` 之后**且平均 ≥ 触发线才武装。瞬时尖峰不触发。
4. 武装即向 eBPF 下发所选算法的策略；流在界面上显示 `LIMITED` 与剩余秒数。
5. 持续 `limit_duration` 后移除策略、清空窗口、回到 NORMAL（若流量仍超触发线，
   满窗后会再次触发——这是预期行为）。

执法是 **policing**：符合速率的包放行，超出即直接丢弃（`TC_ACT_SHOT`）；不做
队列整形（没有 HTB/TBF/netem）——被限流的流表现为丢包，TCP 会收敛到限速值附近。
监控计数点在限速点之前，窗口均值反映的是**需求量**；实际放行/丢弃量看限速裁决计数
（`POLICER_STATS`，详情页 Dropped 列）。

### 算法

六种算法共用同一套触发层，只在"如何判定单个包"上不同；`rx_limit`/`tx_limit`
在每种算法里都是持续速率上限。各算法的完整可运行配置见 [examples/](examples/)。

| 算法 | `algorithm` 值 | 额外字段 | 突发处理 | 数据面开销 |
| --- | --- | --- | --- | --- |
| 令牌桶 Token Bucket | `token_bucket` | `burst` | ≤ `burst` 的突发放行，之后按速率限流 | 极低 |
| 漏桶 Leaky Bucket | `leaky_bucket` | `burst` | 突发进入队列水位，超容量即丢 | 极低 |
| 固定窗口 Fixed Window | `fixed_window` | `limit_window` | 窗口边界处最多可通过 2 倍速率 | 极低 |
| 滑动窗口计数器 Sliding Window Counter | `sliding_window_counter` | `limit_window` | 加权双窗口近似，消除边界突发 | 极低 |
| 滑动窗口日志 Sliding Window Log | `sliding_window_log` | `limit_window` | 精确窗口字节数；需显式开启，每包扫描 1024 条日志环 | 高 |
| GCRA（默认） | `gcra` | `burst` | 突发容忍以时间容忍度表达 | 极低 |

选型建议：拿不准就用默认的 `gcra` 或 `token_bucket`；要最平滑的输出选
`leaky_bucket`；要窗口配额语义（且无边界突发）选 `sliding_window_counter`；
接受边界突发换最简实现选 `fixed_window`；`sliding_window_log` 只建议用于低包率的
精确管控（必须先开 `[experimental] enable_sliding_window_log = true`，并按
`swl_map_max_entries` × 约 16.4 KiB 预分配内核内存）。

### 策略字段

| 字段 | 归属 | 含义 | 约束 |
| --- | --- | --- | --- |
| `rx_threshold` / `tx_threshold` | 方向独立 | 观察阈值 | 100Kbps – 1Tbps |
| `rx_limit` / `tx_limit` | 方向独立 | 武装后被限制到的速率 | 100Kbps – 1Tbps |
| `window` | 共用 | 滚动观察窗口 | > 0（超 3600 个采样截断） |
| `trigger_ratio` | 共用 | 触发线占阈值的百分比 | 1% – 100% |
| `limit_duration` | 共用 | 限速持续时长，到期自动恢复 | > 0 |
| `burst` | 共用 | 桶容量 / GCRA 容忍量（仅桶类与 GCRA） | ≤ 1GiB |
| `algorithm` | 共用 | 限速算法，缺省 `gcra` | 六选一 |
| `limit_window` | 共用 | 窗口长度（仅窗口类算法） | 1s – 60s |

不适用于所选算法的字段会被忽略（因此 override 可以自由继承）。未知算法名在加载期
即被拒绝；数据面遇到未知算法标签一律放行。速率与突发的上下界保证 eBPF 整数运算
永不回绕。

### 限速参数的热加载行为

| 修改 | 行为 |
| --- | --- |
| LIMITED 中改 `rx_limit`/`tx_limit` | 立即按新速率限速 + 重置算法状态 |
| LIMITED 中改 `burst` / `limit_window` / `algorithm` | 立即生效 + 重置算法状态 |
| LIMITED 中改 `limit_duration` | 从原始 `limited_since` 重算 `limited_until`；算出已过期则立即解除 |
| 改 `window` | 观察窗口清空、重新积累 |
| 改 `threshold` / `trigger_ratio` | 保留当前窗口，下一次评估用新触发线 |
| 删除 policy / override | 立即移除限速、恢复 NORMAL |
| 新增 / 删除段 | 白名单与全部状态同步增删；删段清理其限速、算法状态与窗口 |
| `network.bridge`、`collector.refresh_interval_ms`、`map_max_entries`、`swl_map_max_entries` | **不支持热加载**——拒绝并提示重启 |
| 非法配置 | 整份拒绝：保持上一份成功配置，界面顶栏显示 FAILED 与原因 |

## 运维

### 查看与解除限速

- **界面**：总览页 `Limited` 列统计各段限速流数；详情页逐流显示
  `NORMAL`/`LIMITED` 与剩余秒数。
- **日志**：`journalctl -u vm-bandwidth-monitor | grep -iE "limited|trigger|expire"`
- **数据面实证**（最权威）：`bpftool map dump name LIMIT_POLICIES` 与
  `... LIMIT_STATE` 均为 `[]` 即没有任何生效中的限速。

解除方式：删掉该段的 `[ip_ranges.policy]` 块（热加载后全部恢复）、用 override
抬高限速、缩短 `limit_duration`（可能立即解除）、重启（清空全部窗口与状态）、或
等待自动恢复。解除自下一个包起生效；窗口随后重新积累，若流量仍超触发线会再次武装。

### 终端界面（--ui）

总览页列出每个段的实时/累计 RX/TX、已观测 IP 数、限速流数；顶栏显示网桥、TAP 数、
配置 generation 与最近一次 reload 状态。`Enter` 进入按 IP 详情页（实时速率、窗口
均值、有效策略、状态、剩余时间）；趋势屏（单 IP 或整段）覆盖 1h/24h/7d/30d，可切换
带宽/发包量。列集随终端宽度自适应。

| 按键 | 页面 | 功能 |
| --- | --- | --- |
| `↑`/`↓`、`Enter`、`Esc` | 全部 | 导航 |
| `t` | 总览/详情 | 段范围趋势 |
| `Enter` | 详情 | 选中 IP 的趋势（需启用 metrics） |
| `s` | 详情 | 切换排序（IP → RX → TX → 合计） |
| `←`/`→` 或 `1`–`4` | 趋势 | 切换窗口 |
| `b` / `p` | 趋势 | 带宽 / 发包量 |
| `r` | 总览/详情 | 立即刷新 |
| `q` | 总览/详情 | 退出 |

### 历史趋势（VictoriaMetrics）

```bash
cd dist && docker compose up -d     # 单节点，127.0.0.1:8428，保留 35 天
```

然后设置 `[metrics] enabled = true`（参与热加载）。数据模型：每 IP 四条累计计数器
（`vmbw_{rx,tx}_{bytes,packets}_total`，标签 `ip`/`range`）；被限速流另有八条裁决
计数器（`vmbw_policer_{rx,tx}_{passed,dropped}_{bytes,packets}_total`——实际放行/
丢弃量）；另有四条进程级运维计数器（`vmbw_tap_attach_failures_total`、
`vmbw_metrics_push_{successes,failures,skipped}_total`）。daemon 重启造成的计数器
归零由标准 `rate()` 语义处理。

## 实现要点

- **单一 eBPF 对象，挂载到所有 TAP**：对象只加载一次（验证器只跑一遍），同一对
  程序经 TCX（≥6.6）或 netlink clsact 挂到每个 TAP；七份 map（LPM 白名单、
  IPv4/IPv6 计数、策略、状态、SWL 日志、裁决统计）天然共享。
- **VLAN/QinQ**：最多两层 802.1Q/802.1ad 标签（编译期上限）被剥离后按内层
  IPv4/IPv6 进入同一套计数与限速；更深层标签、截断标签与非 IP 载荷一律放行。
- **IPv6 按 TAP 聚合**（key 是 ifindex 而非地址）——隐私地址轮换不会耗尽计数 map。
- 挂载归属精确：只移除本程序创建的 TC filter；共享 qdisc 永不删除；挂载失败按
  指数退避重试。
- 计数为单调累计值，用户态按相邻采样差值计算速率；回绕/复位/TAP 重建周期记 0，
  绝不产生负带宽或虚假触发。
- 闲置键回收：约 5 分钟无变化的计数键被淘汰，有流量回来时数据面在首包重建。
- 单一引擎任务持有全部可变状态，IPC/监听/信号经有界 channel 通信（单写者，
  无共享可变锁）。
- 文件锁防止双开；IPC socket 以 0600 创建。

## 已知边界

- IPv6 只聚合计数（不限速、无按 IP 拆分）；ARP/非 IP 流量不统计；不解析端口、
  连接、payload。
- 超过 65535 字节的报文（如 GSO 聚合帧）不被限速器处理（放行且计入 `oversized`
  观测计数器）。
- `map_max_entries` 耗尽时新的流不再计数、新的限速策略无法安装（数据包仍放行，
  记日志）。
- 累计流量自本次启动起计（每次启动重建 map）。
- 限速是 policing：超限直接丢包，不做缓冲/整形。

## 许可证

本项目按组件双许可：

- **用户态 crates**（`vm-bandwidth`、`vm-bandwidth-core`、`vm-bandwidth-common`）——[MIT](LICENSE)
- **eBPF 程序**（`vm-bandwidth-ebpf`）——[GPL-2.0-only](vm-bandwidth-ebpf/LICENSE)，
  因为它使用了内核的 GPL-only helper（`bpf_spin_lock`）；Linux 内核要求调用
  这类 helper 的程序声明 GPL 兼容许可。

## 文档

- [docs/development.md](docs/development.md) —— 开发工作流与 CI 门禁
- [docs/kernel-validation.md](docs/kernel-validation.md) —— 一次性内核/数据面验证手册
- [docs/production-validation.md](docs/production-validation.md) —— 生产验证记录
- [docs/release.sh](docs/release.sh) —— 发布脚本（changelog → tag → 构建 → 发布）
- [examples/](examples/) —— 各限速算法的可运行配置示例
