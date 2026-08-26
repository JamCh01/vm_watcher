# vm-bandwidth-monitor

[![CI](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml)

实时统计 Linux Bridge（`br0`）下虚拟机按 IPv4 地址划分的网络带宽。
eBPF (TC/SchedClassifier, Aya) 采集，Ratatui 终端界面展示，无数据库、无 HTTP 服务。

- 只统计 `config.toml` 配置的 `开始IP-结束IP` 地址段内的 IPv4 地址，其余一律放行不计数。
- 每个 TAP 接口挂载 TC ingress（VM TX，按源 IP）与 TC egress（VM RX，按目标 IP）。
- TAP 识别不依赖接口名（支持纯数字接口名），按 `tun_flags` 判定；每 5 秒重扫，
  新增/删除 VM 无需重启本程序。
- eBPF 程序只观察计数，任何异常路径都放行数据包（不修改、不重定向、不丢弃）。

## 构建要求

- Linux 宿主机（内核需支持 TC eBPF 与 per-CPU hash map，5.x 以上均可；
  ≥6.6 使用 TCX 挂载，更旧内核走 netlink + clsact）
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
> 若默认 `nightly` 的 LLVM 比本机 bpf-linker 新（报 `Invalid record`），
> 安装一个 LLVM 版本匹配的旧 nightly，然后：
> `VM_BW_EBPF_TOOLCHAIN=nightly-<日期> cargo build --release`。

产物：`target/release/vm-bandwidth-monitor`

> 开发机技巧：`AYA_BUILD_SKIP=1 cargo test` 可以跳过 eBPF 编译，
> 在没有 nightly/bpf-linker 的机器上跑纯用户态单元测试。

## 运行

需要 root（CAP_BPF + CAP_NET_ADMIN），且 `/sys/fs/bpf` 已挂载（通常默认挂载）。

```bash
sudo ./target/release/vm-bandwidth-monitor --config /etc/vm-bandwidth-monitor/config.toml
```

程序启动流程：读取配置 → 校验/去重/查重叠 → 生成 IP 白名单写入 eBPF map →
发现 br0 下的 TAP → 挂载 TC → 每秒采样计算带宽 → TUI。

配置非法（格式错误、名称为空/重复、范围反向、范围重叠）时拒绝启动并指明出错的配置项。

## 配置（config.toml）

```toml
[network]
bridge = "br0"

[collector]
refresh_interval_ms = 1000        # 采样/刷新周期
interface_scan_interval_secs = 5  # TAP 重扫周期
map_max_entries = 8192            # TRAFFIC map 容量（(ifindex, IP) 对）

[display]
show_interface = false            # 详情页显示 IP 对应的 TAP 接口列
show_packets = false              # 详情页显示累计包数列
default_sort = "ip"               # 详情页初始排序: ip | rx | tx | total

[[ip_ranges]]
name = "VM-Network-1"
range = "10.30.8.1-10.30.8.16"

[[ip_ranges]]
name = "VM-Network-2"
range = "10.30.9.1-10.30.9.32"
```

只支持 `开始IP-结束IP`；不支持 CIDR、通配符、反向范围。IP 段之间不允许重叠。

## 界面

默认进入 **IP Range Overview**：每个段的名称、范围、实时 RX/TX、累计 RX/TX。
选中后按 `Enter` 进入 **IP Range Detail**：段内**每一个** IP（包括零流量的）。

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

- **每个 TAP 一个 eBPF 对象实例**：`aya` 的 `TcContext` 拿不到 `skb->ifindex`，
  因此每个 TAP 单独加载一份对象，用 `override_global("IFINDEX", ...)` 把 ifindex
  烙进 `.rodata`；两份 map（白名单、计数）通过 bpffs pin 共享。
- 挂载/卸载由 `AttachManager` 负责：丢弃某实例即移除**且仅移除**本程序创建的
  TC filter；不动 `fq_codel`/`noqueue`，不清理其他程序的 filter。
- 计数为单调累计值，用户态按相邻两次采样差值 × 8 ÷ 实际间隔秒数计算速率；
  计数回绕/复位时该周期记 0，绝不产生负带宽。
- 单个 TAP 挂载失败不影响其他 TAP，下个扫描周期自动重试。
- `/run/vm-bandwidth-monitor.lock` 文件锁防止双开；
  启动时清理上一次运行遗留的 pin，退出时再清理一次。

## 已知边界（v1）

- 不统计 IPv6/ARP/非 IP 流量；不解析端口、连接、payload。
- `map_max_entries` 耗尽时，新的 `(ifindex, IP)` 对不再计数（数据包仍放行）。
  VM 频繁重建会产生新 ifindex 的历史键；默认 8192 容量下余量充足。
- 累计流量自本次启动起计（每次启动重建 map）。
- 无配置热加载：修改 `config.toml` 后需重启。
