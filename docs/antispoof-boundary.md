# 反欺骗边界：必须在 TC ingress 之前（裁决证据与部署要求）

**状态**：裁决完成（2026-08-29，实验室）；要求已并入 `README.md` 安全前提清单第 5 项。
**适用**：所有部署本程序的宿主。反欺骗本身仍由外部强制（本程序不持有），但
强制点的**位置**有硬性要求。

## 1. 实测钩子顺序

环境：Debian 13，kernel 6.12.73+deb13-cloud-amd64，TCX 附着 + `nftables` netdev
ingress 链同时在位。注入伪造源帧后：

- `TRAFFIC` map（TC 层计数）计入了伪造帧；
- 随后 nft netdev-ingress 计数器才记录 drop，对端收到 0 帧。

**结论：TC ingress 先于 nftables netdev-ingress。** Linux 接收路径上唯一早于
TC ingress 的通用钩子是 **XDP**。

## 2. 跨租户影响裁决（F1）

拓扑：bridge + tapA（VM-A，10.99.0.1）+ tapB（VM-B，10.99.0.2），双端 300Kbps
token_bucket 策略；外部反欺骗 = nft netdev ingress 白名单（TCX 之后）。
攻击：VM-A 全速伪造 `src=10.99.0.2`；受害：VM-B 以 150Kbps 发合法流量。

| 阶段 | 边界 | victim 发送 | victim 到达 | armed | POLICER(B,TX) |
|---|---|---|---|---|---|
| 基线 | nft(after TCX) | 3538 | 3442 (97%) | 0 | 无 |
| 攻击 | nft(after TCX) | 3538 | **1009 (-70.7%)** | 1 | dropped 1.72GB |
| 攻击后 | nft(after TCX) | 7076 | 7065 (99.8%) | ≤10s 解除 | — |
| 攻击 | **XDP(before TCX)** | 3538 | **3441 (97%，无衰减)** | **0** | 无 |

攻击规模：两组分别为 17,070,000 与 19,569,342 伪造帧，**对端到达均为 0**
（反欺骗本身 100% 有效）。差异仅在强制点位置：

- **nft（TCX 之后）**：伪造帧先被计入受害者 (IP,TX) 预算并武装限速器，受害者
  合法帧随即被限速器丢弃——合法吞吐 -70.7%。攻击者自身 (10.99.0.1) 预算零消耗
  （伪造帧记在受害者键上），属跨租户带宽 DoS；
- **XDP（TCX 之前）**：伪造帧在计数前被丢弃，`TRAFFIC(B,tapA)` delta=0，
  限速器从未武装，受害者吞吐无衰减。合法帧放行验证：10.99.0.1 → 对端 4/4。

攻击停止后恢复快（≤10s）是因为受害者单独速率低于限额，罚时尾部不再丢包；
攻击持续期间损害线性累积。

## 3. 部署要求

1. 源地址反欺骗必须强制在 **TC ingress 之前**：XDP（generic 即可）或等效的
   驱动层/交换机端口安全。netdev-ingress `nftables`/`ebtables` 在**桥接路径**上
   是有效的反欺骗，但对**本程序的计数**而言位置太晚——两者可以并存，预算保护
   必须由前置的那一层提供。
2. 每个 TAP 一个按租户定制的边界程序。参考实现：`scripts/antispoof-xdp/antispoof_xdp.c`
   （自包含、`clang -O2 -target bpf` 即可编译，头部注释说明逐 TAP 定制方法）。
3. 部署核对：`scripts/antispoof-xdp/verify-boundary.sh <bridge>` 检查桥下每个
   TAP 是否挂有 XDP 程序（附着核对）；顺序的端到端证明见第 4 节。

## 4. 端到端验证步骤（一次性环境执行）

1. 正常部署（反欺骗在位），记下 `bpftool map dump name TRAFFIC` 中某受监控
   IP 的计数；
2. 从另一 TAP 注入若干伪造该 IP 源的帧；
3. 若 TRAFFIC 计数**不变**且对端收 0 帧 → 边界在 TC 之前，合格；
   若计数**增加**（哪怕对端仍收 0 帧）→ 强制点在 TC 之后，不合格。

## 5. TAP 重建生命周期

XDP 附着与 netdev 钩子都绑定在设备上：TAP 删除重建（新 ifindex）后，旧
ifindex 上的一切强制全部失效。daemon 侧行为：

- 检测到重建 → 自动重新附着自身的 TC 程序（既有行为）；
- 同时输出 `SECURITY` 告警并累计 `antispoof_reapply_alerts_total`
  （IPC `Status` 字段 + `vmbw_antispoof_reapply_alerts_total` 指标）；
- **重挂反欺骗规则不在本程序职责内**——平台收到告警后必须重挂。

## 6. 实验室出处

证据目录：103.73.220.152 `/var/tmp/vmbw-validation-20260829T155324Z-daeb299/lab/`
（`F1-ADJUDICATION.md`、`f1-adjudication/*.pcap`、`f1-xdp/`）。
二进制：PR #5 head `daeb299`，sha256
`1ac27741da40b2b4b7d702a2acab71a3226082b3058c31b6baf53968b7b872d9`。
