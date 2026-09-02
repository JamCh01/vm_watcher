# 内核/数据面验证手册（仅限一次性测试环境）

本手册的所有步骤都**禁止在生产宿主机执行**：它们会创建网络设备、挂载测试程序、
注入流量。请在一台可随时销毁的 Linux VM 或 `unshare -n` netns 环境中进行。

约定：

```bash
TESTHOST="一次性 VM/netns"      # 内核版本尽量接近生产（生产当前为 6.12）
BIN=./vm-bandwidth-monitor      # 与生产同版本构建（release，含 eBPF 对象）
```

---

## 1. VLAN / QinQ 解析验证（用户态向量测试已通过，此处验证真实内核路径）

用户态已用帧向量钉死判定逻辑（`vm-bandwidth-common` 的 `vlan_walk` 测试）；
真实内核验证走 netns + veth + VLAN 子接口：

```bash
# 准备：一对 veth，一端模拟 "VM"，另一端挂本程序
ip netns add vmtest
ip link add veth0 type veth peer name veth1
ip link set veth1 netns vmtest
ip link add br-test type bridge
ip link set veth0 master br-test
ip link set br-test up

# VM 侧打单层 802.1Q 标签
ip netns exec vmtest ip link add link veth1 name veth1.100 type vlan id 100
ip netns exec vmtest ip addr add 10.99.0.2/24 dev veth1.100
ip netns exec vmtest ip link set veth1 up
ip netns exec vmtest ip link set veth1.100 up

# 配置：把 10.99.0.0 段加入白名单，bridge = br-test
# 启动 daemon（前台，RUST_LOG=debug），然后：
ip netns exec vmtest ping -c 5 10.99.0.1 || true     # 产生带标签的 ICMP
```

判定：

- [ ] `--ui` / IPC 中该段出现 10.99.0.2 且计数随流量增长（单层 802.1Q 进入计数与限速）；
- [ ] 同法用 `type vlan` 之上再套一层验证 QinQ（内层计数正确）；
- [ ] 三层标签：计数不增长且不崩溃（fail-open 放弃）；
- [ ] 截断帧：`scapy`/`mausezahn` 发送短于 4 字节标签的帧，程序不退出、不误计。

清理：`ip netns del vmtest; ip link del br-test`。

## 2. GSO/TSO/超大 skb 判定（oversized 观测项）

数据面对 `len > 65535` 的包放行（`MAX_POLICED_LEN`），并用 `OVERSIZED` map 计数
（仅在该流有武装策略时）。判定该环境是否真的会把超大帧递给 TAP 的 TC 挂钩：

```bash
# 0) 给测试段的策略配一个很低的阈值使其必然 LIMITED（观察期保持武装）
# 1) 基线：默认 offload
ethtool -k "$TAP" | grep -E 'gso|gro|tso|gso_max_size'
cat /sys/class/net/"$TAP"/gso_max_size        # 若 > 65536 说明支持 BIG TCP
# 2) 跑满流量（测试 VM 内 iperf3 大窗口多线程），读取：
#    - IPC Status.oversized_rx_packets / oversized_tx_packets（或 vmbw_oversized_* 指标）
# 3) 关闭 offload 再测一轮对照：
ethtool -K "$TAP" tso off gso off gro off
# 4) 若内核支持 BIG TCP，打开再测：
ip link set dev "$TAP" gso_max_size 196608     # 仅测试机！
```

判定矩阵（把结果写回发布说明）：

| 场景 | oversized 计数 | 结论 |
|---|---|---|
| 默认 | 0 | 该平台无超大帧抵达，当前放行语义无实际绕过 |
| 默认 | >0 且随流量增长 | **真实绕过存在**：需要实现按实际字节收费的超大帧处理（不得 clamp 低估、不得误杀），升级为发布阻断项 |
| 仅 BIG TCP 打开 | >0 | 记录为已知限制，并在平台侧禁用 BIG TCP 或实现处理 |

**未在此完成裁决前，不得声称 GSO 风险已关闭。**

## 3. 传统（<6.6）内核的 legacy TC 回退

生产为 6.12（TCX 路径），旧内核回退仅由 `FakeBackend` 测试覆盖。需要一台 <6.6
的一次性内核（如 Debian 12 的 6.1）：

- [ ] 启动后日志为 "reusing existing clsact" 或 "created clsact for legacy TC attach"
      （不是 TCX）；
- [ ] `tc filter show dev $TAP ingress`/`egress` 能看到本程序 filter；
- [ ] 停止后：本程序创建的 clsact 按设计**保留**（日志有说明），根 qdisc 未动；
- [ ] 预先 `tc qdisc add dev $TAP ingress`（legacy 独占 qdisc）再启动：
      日志应诊断 "legacy ingress qdisc conflicts"，且该 TAP 无半挂载
      （没有只挂 ingress 不挂 egress 的状态）。

## 4. SWL 性能/语义基准（仅在显式启用后）

```toml
[experimental]
enable_sliding_window_log = true
[collector]
swl_map_max_entries = 4
```

- [ ] 低包率流（< 1024/limit_window pps）：限速贴合配额（对照 `swl.rs` 参考模型）；
- [ ] 高包率流（远超 1024/window pps）：判定偏宽松（放行量超配额），与模型预测一致；
- [ ] `bpftool map show` 记录 `SWL_LOG` 实际 `bytes_memlock`/内存，核对 `条数 × 16.4 KiB`；
- [ ] `perf top` 观察 `swl_police` 占比，记录该算法可接受的包率上限（写回文档）。

## 5. 缺席键删除的 errno 变体（计数器清理依赖项）

前置条件：

- Linux 宿主机 + **root**（`bpftool map create` 与 BPF syscall 需要 `CAP_BPF`/root）；
- bpffs 已挂载（默认 `/sys/fs/bpf`）。未挂载时先 `mount -t bpf bpf /sys/fs/bpf`（root）；
- 安装 `bpftool`。**本节所有命令默认不在开发环境执行**——需要上述环境时按步骤跑。

背景：counter map 的空闲淘汰与 stale-TAP 清理（`daemon.rs::remove_counter_keys` /
`PendingRemovals`）把“键本就不在”视为删除成功。判定按**类型化错误变体**匹配，
绝不做错误字符串匹配：

- `MapError::KeyNotFound` / `MapError::ElementNotFound`；
- `MapError::SyscallError(se)` 且 `se.io_error.kind() == NotFound`；
- `MapError::IoError(io)` 且 `io.kind() == NotFound`。

aya 0.14 的 `hash_map::remove` 把 `bpf_map_delete_elem` 的失败包成
`SyscallError`（源码路径已核对），因此内核返回 ENOENT 时落入第二个变体——但
**内核实际返回的 errno 未在真实环境裁决过**。在那之前代码保持保守：未匹配的
变体一律计为失败、按键记日志、下一个有界维护周期重试，绝不静默当成功。

验证步骤（均需 root）：

```bash
# 0. 环境检查
uname -r                # 记录内核版本
bpftool version         # 记录 bpftool 版本
mountpoint -q /sys/fs/bpf || { echo "bpffs 未挂载"; exit 1; }

# 1. 创建探针 map（官方语法：bpftool map create FILE type TYPE key KEY_SIZE
#    value VALUE_SIZE entries MAX_ENTRIES name NAME）。pin 路径带 PID，
#    不覆盖已有 pin。
PROBE_PIN="/sys/fs/bpf/vmbw-delete-probe-$$"
cleanup() { rm -f -- "$PROBE_PIN"; }
trap cleanup EXIT

bpftool map create "$PROBE_PIN" \
    type hash \
    key 4 \
    value 4 \
    entries 8 \
    name vmbw_del_probe

bpftool map show pinned "$PROBE_PIN"

# 2. 删除一个从未写入的键，记录 exit status 与 stderr
bpftool map delete pinned "$PROBE_PIN" key 0 1 2 3
echo "exit=$?"
bpftool map delete pinned "$PROBE_PIN" key 0 1 2 3 2>&1 | cat

# 3. trap 清理本任务创建的 pin；不得删除任何非本任务创建的 map
```

记录要求：命令、exit status、stderr 原文、内核版本（`uname -r`）、bpftool 版本、
Cargo.lock 中的 aya 版本，以及 Rust 侧最终匹配到的类型化变体。

判定标准：

- [ ] **最终裁决必须落在 Rust 侧**：bpftool 的 stderr 字符串只是线索，不得把
      它直接等同于 aya 的枚举变体。最小探针（对缺席键调用
      `HashMap::remove` 并打印 `MapError` 变体）或本程序真实代码路径（观察到
      缺席键清理记为 `removed` 且无 `remove failed` 日志）确认类型化变体后，
      记录结论；
- [ ] 缺席键删除返回 ENOENT 且落入上述匹配变体 → 现有类型化匹配成立；
- [ ] 返回其它 errno/变体 → 在 `key_already_absent` 的匹配分支中补上该变体
      （仍按类型，不按字符串），并回归本节。

本项未闭环前，不得声称“缺席键即成功”已在生产内核验证；默认 CI 不要求 root，
故本节只存在于文档。

---

以上任何一项的结果变化（内核升级、offload 策略变化、平台过滤规则变化）都应重新
执行对应章节，并把结论记录到发布说明与 `known-limitations`。
