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

## 未验证（保持开放）

- 新 head 的生产部署；
- GSO/oversized 的真实裁决；
- 外部反欺骗在生产桥/平台层的实际有效性（`kernel-validation.md` §5 方案）；
- <6.6 内核的 legacy TC 回退（生产为 6.12，走 TCX）。
