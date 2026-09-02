# 生产验证记录

本文件记录在生产宿主机（Linux bridge 宿主机，内核 6.12.101，112 个 TAP 全走 TCX）
上完成的验证。**所有证据都绑定到具体的提交**，不得跨 head 归属。

## 已验证：旧 head `75fe240afb82565a1f3810481083bb07693c04b2`（PR #2 首个 head）

- CI：run `33198045448`（userspace 与 eBPF build 两个 job 全绿）
- 部署产物：该 run 的 `vm-bandwidth-monitor-linux-x86_64` artifact，
  md5 `f191dd69bddd152f9f56ec39e128ccc8`（两端校验一致）
- 部署日期：2026-08-28

### 实测证据

| 项 | 结果 |
|---|---|
| 安全门（负） | 无 `[security]` 确认时 v0.7.0 拒绝启动，错误消息与代码一致 |
| 安全门（正） | 确认后启动，`SECURITY: ip_ownership = "external"…` warn 日志 |
| SWL 内存 | `bpftool map show`：`SWL_LOG` memlock `135,467,392 B`（v0.6.6，8192 条）→ `4,745,600 B`（v0.7.0，256 条），-96.5% |
| IPv6 重键 | `TRAFFIC6` key 变为 4 B（u32 ifindex） |
| OVERSIZED map | 存在（key 1 B，max_entries 4） |
| IPC Status | `protocol_version=1`、`anti_spoof_*`、`swl_map_capacity/used`、`dataplane_degraded=false`、`oversized_*=0`、watcher healthy |
| lockfile | 停机后保留（`LOCKFILE-PERSISTED`） |
| 热加载 | 探针注释触发：generation `1 → 2`，0 错误 |
| metrics | `sum(vmbw_rx_bytes_total)` 70 s 增长 ≈ 636 Mbit/s，与实际流量吻合 |
| 挂载 | 112 个 TAP 全部 TCX；`--version` 输出 `0.7.0` |

### 证据边界（必读）

1. 上述证据**只对应旧 head `75fe240a`**。此后针对回滚 disarm 失败与 IPC 双向
   帧上限的修复（`fix(txmaps)…`、`fix(ipc)…` 及对应测试提交）**尚未经过相同的
   生产部署验证**；新 head 的可信度以单元测试、集成测试与 GitHub Actions 为准。
2. 验证窗口内 `LIMIT_POLICIES` 无武装条目（流量低于所有触发阈值），因此
   `oversized_* = 0` **不能裁决 GSO/oversized 问题**——观测路径当时不可达。
   裁决需在出现武装策略的流量窗口内读数（见 `kernel-validation.md` §2）。
3. `vmbw_rx_bps` 等速率序列在任何版本都不存在（v0.5.0 起只推送累计 `_total`
   序列，速率由趋势屏/查询侧 `rate()` 推导）——这是**历史行为，不是本次回归**。

## 已验证：main head `031738c`（PR #6 squash，含 PR #5 等价变更集）

- 身份链：tree `74c60c080f6413065d6c78e041c31ce2161f347d`（合并后 main tree 逐字节
  一致）；CI run `33265806329`（userspace 与 eBPF build 全绿）；部署产物为该 run 的
  `vm-bandwidth-monitor-linux-x86_64` artifact，sha256
  `21f2dbb6a980d190797b06db96d353c2b3597d46b39c0f91bd0105a26ed0e8d5`
  （11,140,472 B；本地与生产两端校验一致，安装后复验仍一致）。来源说明：PR #6 分支自 `daeb299`
  （当时未合并的 PR #5 head）检出，squash 对 base 展开后同时包含 PR #5 全部修复；
  PR #5 已据此关闭，不再单独归属。
- 替换前二进制：sha256 `7b98b9da726fd4b887cbb291eb1dd3b1dd241d30723ddc05547f57261e16a83e`
  （head `75fe240a`，2026-08-28 部署，运营确认此后未更新），备份为
  `/usr/local/bin/vm-bandwidth-monitor.bak-1788025710`。
- 部署：2026-08-29 17:48:31 UTC SIGTERM → `daemon stopped cleanly` → 17:48:36
  systemd 拉起新进程（停机 ≈5s）；配置 `/root/config.toml` 未动。
- 宿主：`cust-2785-7288`，kernel 6.12.101+deb13-amd64，br0 113 端口（112 TAP），
  systemd 单元 `vm-bandwidth-monitor.service`（Restart=on-failure，日志入 journal）。

### 实测证据

| 项 | 结果 |
|---|---|
| 启动 | 11 IP 段、whitelist 50 CIDR 前缀覆盖 130 个 IPv4；`SECURITY: ip_ownership = "external"` warn |
| 挂载 | 112 TAP 全部 TCX（ingress+egress 共 224 条），`initial scan: 112 attached, 0 failed` |
| IPC Status | `protocol_version=1`、`generation=1`、`dataplane_degraded=false`、watcher healthy、`rollback_failures_total=0`、`tap_attach_failures_total=0` |
| 新字段 | `antispoof_reapply_alerts_total=0` 存在（PR #6 新增；正例路径仅实验室验证过） |
| metrics | 200s 观察窗内推送 1→4 成功、0 失败；VictoriaMetrics
  `sum(vmbw_tx_bytes_total)` 实时可查且与 TRAFFIC 总量吻合（推送周期内的正常滞后） |
| 流量 | 观察窗内 `TRAFFIC` tx 累计 +14.6 GB / 200s ≈ **584 Mbit/s**，与生产流量量级吻合 |
| 内核 | dmesg 无 bpf/lockup/rcu/stall |
| TUI | tmux `vmbw` 会话随新二进制重启正常 |
| Seednet sell-2（8/10 之问） | **非缺陷**：配置 10 个 IP，`.136` 与 `.139` 自上次启动以来零流量，
  收集器按设计不枚举无流量地址（collector `ips` = “启动以来观测到的 IP”）；
  TRAFFIC map 实测仅该 8 个 IP 有条目，其余各段同样模式（如 hinet sell-0 13/16） |

### 证据边界（必读）

1. 观察窗内 `LIMIT_POLICIES` 无武装条目（流量低于所有触发阈值，当前配置无 policy），
   `oversized_* = 0` 依然**不能裁决 GSO/oversized**；需在武装窗口内读数。
2. `antispoof_reapply_alerts_total` 的正例（TAP 重建触发告警）只在实验室验证；
   生产观察窗内无重建事件，计数保持 0 属预期。观察窗内曾见新 TAP **创建**
  （非重建），正确地未触发该计数。
3. 外部反欺骗层在生产桥上的实际部署形态与有效性未在本次窗口内核查（保持开放）。

## 未验证（保持开放）

- GSO/oversized 的真实裁决（需武装策略窗口）；
- 外部反欺骗在生产桥/平台层的实际有效性（`kernel-validation.md` §5 方案）；
- `antispoof_reapply_alerts_total` 生产正例（等待自然发生的 TAP 重建）；
- <6.6 内核的 legacy TC 回退——**已放弃**（2026-08-30 决策：生产为 6.12 走 TCX，
  无旧内核环境，不再投入）。
