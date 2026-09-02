# vm-bandwidth-monitor

[![CI](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml/badge.svg)](https://github.com/JamCh01/vm_watcher/actions/workflows/ci.yml)

[English](README.md) | [简体中文](README.zh-CN.md) | **日本語**

Linux ブリッジ上の仮想マシンについて、IPv4 アドレスごとの帯域幅をリアルタイムに集計し、
IP レンジ / 単一 IP に対して**レート制限**を行えるデーモンです。eBPF (TC/SchedClassifier,
Aya) のデータプレーンがカウントとポリシングを担当し、常駐デーモンが観測ウィンドウと
制限状態機械を駆動します。読み取り専用のターミナル UI（`--ui`）でリアルタイム値と
履歴を表示でき、`config.toml` はホットリロードに対応。デフォルトではデータベースも
HTTP サーバも持ちません。任意で累計カウンタを VictoriaMetrics に送信し、任意の IP の
履歴トレンドを確認できます。

- 集計対象は `config.toml` に設定した `開始IP-終了IP` レンジの IPv4 のみ。それ以外は
  カウントせず通過させます。レンジは最小の CIDR プレフィックス集合に分解され、
  eBPF **LPM トライ**（`MONITORED_IPS`）に格納されるため、レンジの大きさは map 使用量に
  影響しません。IPv6 は別途集計されます（カウントのみ、制限なし、IP ごと拆分なし）。
- 各 TAP インターフェースに TC ingress（VM TX、送信元 IP 基準）と TC egress
  （VM RX、宛先 IP 基準）を装着します。TAP は `tun_flags` で判定し、インターフェース名に
  依存しません。周期的に再スキャンするため、VM の増減に再起動は不要です。
- **レート制限**：各 `(IP, 方向)` が移動平均ウィンドウを持ち、
  `threshold × trigger_ratio` を超えると選択したアルゴリズムのポリシーを eBPF に
  インストールし、`limit_duration` 経過後に自動回復します。
- **ホットリロード**：`config.toml` の編集はトランザクション的に自動適用されます
  （ファイル監視 + `SIGHUP`）。失敗時は最後に成功した設定へロールバックします。
- データプレーンは観測カウントとポリシングのみ。あらゆる異常パスは fail-open です。

## 特徴

- IP ごとのリアルタイム／累計 RX/TX バイト数・パケット数（1 秒サンプリング）
- レンジごとに選択可能な 6 種のポリシングアルゴリズム（デフォルト GCRA）— [examples/](examples/) 参照
- 観測トリガ型の適用：NORMAL/LIMITED ライフサイクル、期限後の自動回復
- 単一 IP のポリシーオーバーライド（フィールド単位で継承）
- トランザクション的ホットリロード。不正な設定でも監視は中断しない
- 読み取り専用ターミナル UI：レンジ概要、IP 詳細、1h/24h/7d/30d トレンド
- 任意の VictoriaMetrics 送信（累計カウンタ、標準の `rate()` クエリ）
- 読み取り専用の Unix socket IPC。データプレーンの所有者は構造的に単一
- 正常シャットダウン：本プログラムが作成した TC 装着のみを削除し、map pin を清掃
- 全面 fail-open：本プログラムのいかなる異常も VM のネットワークを壊さない

## ワークスペース構成

| crate | 役割 |
| --- | --- |
| `vm-bandwidth-common` | eBPF とユーザ空間で共有する `#[repr(C)]` 型（トラフィック/制限キー、SWL リング、アルゴリズム定数） |
| `vm-bandwidth-ebpf` | TC classifier：カウンタ + マルチアルゴリズム policer（no_std、nightly） |
| `vm-bandwidth-core` | 純粋ロジック：単位パース、設定検証、ポリシー継承、ウィンドウ、制限状態機械、IPC 型。aya 非依存、どのプラットフォームでも単体テスト可能 |
| `vm-bandwidth` | ランタイム：デーモン、eBPF 読み込み、IPC サーバ、ホットリロード、`--ui` クライアント（バイナリ `vm-bandwidth-monitor`） |

## ビルド要件

- Linux ホスト（TC eBPF、per-CPU ハッシュマップ、`bpf_spin_lock` 対応のカーネル。
  カーネル ≥ 6.6 は TCX、より古いカーネルは netlink + clsact にフォールバック）
- Rust stable ≥ 1.89 と **nightly**（`aya-build` が `-Z build-std` で eBPF 部をコンパイル）
- `bpf-linker`：`cargo install bpf-linker`
- nightly 用 `rust-src`：`rustup component add rust-src --toolchain nightly`

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo build --release
```

> eBPF バイトコードは nightly の LLVM が生成します。bpf-linker は自身の LLVM
> バージョン以下のビットコードしか読めません。デフォルトの `nightly` が新しい場合
> （`Invalid record` エラー）、LLVM バージョンが一致する古い nightly を入れて
> `VM_BW_EBPF_TOOLCHAIN=nightly-<日付> cargo build --release` としてください。

成果物：`target/release/vm-bandwidth-monitor`

> 開発向け：`AYA_BUILD_SKIP=1 cargo test` で eBPF ビルドをスキップできます。
> `vm-bandwidth-core` の純粋ロジックのテストは Linux 不要です。

## クイックスタート

root 権限（CAP_BPF + CAP_NET_ADMIN）が必要で、`/sys/fs/bpf` がマウント済みであること
（通常はマウント済み）。

```bash
# デーモン（運用形態：systemd 管理）
sudo ./target/release/vm-bandwidth-monitor --config config.toml

# 読み取り専用ターミナル UI（稼働中のデーモンへ接続）
./target/release/vm-bandwidth-monitor --ui
```

起動手順：設定を読み込み完全に検証 → fd 上限を引き上げ → レンジを CIDR
プレフィックスに分解して `MONITORED_IPS` へ → ブリッジ配下の TAP を検出して TC を装着
→ 毎秒サンプリングしウィンドウとリミッタを駆動 → `/run/vm-bandwidth-monitor.sock`
で読み取り専用 IPC を提供 → 設定ファイルを監視。

`SIGINT`/`SIGTERM` でクリーンに終了（本プログラムが作成した TC 装着のみ削除、
map pin と socket も削除）。`SIGHUP` で設定リロードを 1 回実行。`--ui` クライアントは
eBPF の再読み込み、map 作成、TC 装着を一切行いません。データプレーンの所有者は
デーモンただ一つです。

## 設定（config.toml）

```toml
[network]
bridge = "br0"

[collector]
refresh_interval_ms = 1000        # サンプリング周期（ウィンドウの刻みでもある）
interface_scan_interval_secs = 5  # TAP 再スキャン周期
map_max_entries = 8192            # TRAFFIC / LIMIT_POLICIES / LIMIT_STATE / SWL_LOG の容量

[display]
default_sort = "ip"               # --ui 詳細ページの初期ソート: ip | rx | tx | total
# show_idle_ips = true            # レンジ内の全アドレスを列挙（トラフィック 0 も 0 行で表示）。
                                  # デフォルトはオフ。4096 アドレス超のレンジは常に列挙しない

[metrics]                         # 任意：履歴トレンド（VictoriaMetrics）
enabled = false
url = "http://127.0.0.1:8428"
push_interval_secs = 60

[[ip_ranges]]
name = "VM-Network-1"
range = "10.30.8.1-10.30.8.16"

  [ip_ranges.policy]              # このブロックを省略 = 監視のみ
  rx_threshold = "1Gbps"
  tx_threshold = "500Mbps"
  window = "5m"
  trigger_ratio = "80%"
  rx_limit = "500Mbps"
  tx_limit = "200Mbps"
  limit_duration = "30m"
  burst = "4MiB"

  [[ip_ranges.overrides]]         # 単一 IP の例外（フィールド単位でマージ）
  ip = "10.30.8.3"
  rx_threshold = "2Gbps"
  rx_limit = "800Mbps"
```

ルール：

- レンジは `開始-終了` のみ（CIDR、ワイルドカード、逆順は不可）。レンジ間の重複は不可。
- `policy` は任意。省略すると監視のみ。`rx_threshold`/`tx_threshold`、
  `rx_limit`/`tx_limit` は方向ごと独立。`window`、`trigger_ratio`、`limit_duration`、
  `burst` は両方向共用。ある方向のフィールドが一部だけの場合は拒否されます。
- 単位：レート `100Mbps`/`1Gbps`（10 進）、時間 `5m`/`30m`/`1h`、パーセント `80%`、
  バースト `4MiB`（2 進）。すべて整数のみ（浮動小数点は不可）。
- オーバーライドの IP は所属レンジ内で、レンジごとに一意であること。未記入の
  フィールドはレンジのポリシーを継承します。
- `[metrics]`（任意、デフォルトはオフ）：`push_interval_secs`（5〜3600）秒ごとに
  累計カウンタを送信。ローカルホストの `http://` は許可、リモートは
  `allow_insecure_http = true` を明示しない限り `https://` 必須。

## レート制限

リミッタは**観測トリガ型**です。各 `(IP, 方向)` は独立に判定されます
（RX と TX を合算することは絶対にありません）。

1. トリガーライン = `threshold × trigger_ratio`（例：`1Gbps × 80% = 800Mbps`）。
2. デーモンは毎秒バイト増分をサンプリングして移動ウィンドウを維持。
   ウィンドウ平均 = `ウィンドウ内の総バイト × 8 ÷ 実際の観測時間`。
3. ウィンドウが `window` 全体を満たした**後にのみ**、平均がトリガーライン以上なら
   アームします。瞬間的なスパイクではトリガしません。
4. アームすると選択アルゴリズムのポリシーを eBPF にインストール。フローは
   `LIMITED`（残り秒数つき）として表示されます。
5. `limit_duration` 経過後、ポリシーは削除され、ウィンドウはクリアされ、フローは
   NORMAL に戻ります（トラフィックがなお超えていれば再アームします。これは仕様です）。

適用は **policing** です：準拠パケットは通過、超過パケットは即ドロップ
（`TC_ACT_SHOT`）。キューイング/シェーピングなし（HTB/TBF/netem は使いません）。
制限されたフローは損失として振る舞い、TCP は制限値付近に収束します。監視カウンタは
ポリサーの前にあるため、ウィンドウ平均は**需要量**を反映します。実際の通過/破棄量は
ポリサー判定カウンタ（`POLICER_STATS`、詳細ページの Dropped 列）で確認できます。

### アルゴリズム

6 種ともトリガ層は共通で、パケットごとの判定のみが異なります。どのアルゴリズムでも
`rx_limit`/`tx_limit` は持続レートの上限です。各アルゴリズムの動作する設定例は
[examples/](examples/) にあります。

| アルゴリズム | `algorithm` 値 | 追加フィールド | バースト挙動 | データプレーン負荷 |
| --- | --- | --- | --- | --- |
| トークンバケット | `token_bucket` | `burst` | `burst` 以下のバーストは通過、以降はレート制限 | 超低 |
| リーキーバケット | `leaky_bucket` | `burst` | バーストはキュー水位に入り、容量超過でドロップ | 超低 |
| 固定ウィンドウ | `fixed_window` | `limit_window` | ウィンドウ境界で最大 2 倍レートが通過しうる | 超低 |
| スライディングウィンドウカウンタ | `sliding_window_counter` | `limit_window` | 2 ウィンドウの重み付き近似。境界バーストなし | 超低 |
| スライディングウィンドウログ | `sliding_window_log` | `limit_window` | 厳密なウィンドウバイト数。要明示的有効化、パケットごとに 1024 エントリのリングを走査 | 高 |
| GCRA（デフォルト） | `gcra` | `burst` | バースト許容量を時間許容量として表現 | 超低 |

選定の指針：迷ったらデフォルトの `gcra` か `token_bucket`。最も滑らかな出力が
欲しければ `leaky_bucket`。ウィンドウ割当てセマンティクス（境界バーストなし）なら
`sliding_window_counter`。境界バーストを受け入れて最も単純な実装を選ぶなら
`fixed_window`。`sliding_window_log` は低パケットレートで厳密なウィンドウが
必要な場合のみ推奨（`[experimental] enable_sliding_window_log = true` が必須、
`swl_map_max_entries` × 約 16.4 KiB のカーネルメモリを事前確保）。

### ポリシーフィールド

| フィールド | スコープ | 意味 | 制約 |
| --- | --- | --- | --- |
| `rx_threshold` / `tx_threshold` | 方向ごと | 観測しきい値 | 100Kbps – 1Tbps |
| `rx_limit` / `tx_limit` | 方向ごと | アーム後の制限レート | 100Kbps – 1Tbps |
| `window` | 共用 | 移動観測ウィンドウ | > 0（3600 サンプルで頭打ち） |
| `trigger_ratio` | 共用 | しきい値に対するトリガーラインの割合 | 1% – 100% |
| `limit_duration` | 共用 | 制限の継続時間、経過後に自動回復 | > 0 |
| `burst` | 共用 | バケット容量 / GCRA 許容量（バケット系 + GCRA のみ） | ≤ 1GiB |
| `algorithm` | 共用 | ポリシングアルゴリズム、既定は `gcra` | 6 種から 1 つ |
| `limit_window` | 共用 | ウィンドウ長（ウィンドウ系のみ） | 1s – 60s |

選択したアルゴリズムに適用されないフィールドは無視されます（オーバーライドが自由に
継承できるようにするため）。未知のアルゴリズム名は読み込み時に拒否されます。
データプレーンは未知タグを fail-open で扱います。レートとバーストの上下限は、
eBPF の整数演算がオーバーフローしないことを保証するためのものです。

### 制限パラメータのホットリロード挙動

| 変更 | 挙動 |
| --- | --- |
| LIMITED 中に `rx_limit`/`tx_limit` 変更 | 即座に新レートで制限 + アルゴリズム状態をリセット |
| LIMITED 中に `burst` / `limit_window` / `algorithm` 変更 | 即時反映 + 状態リセット |
| LIMITED 中に `limit_duration` 変更 | 元の `limited_since` から `limited_until` を再計算。期限切れなら即解除 |
| `window` 変更 | 観測ウィンドウをクリアし、再蓄積 |
| `threshold` / `trigger_ratio` 変更 | 現在のウィンドウを維持し、次回評価から新トリガーライン |
| policy / override 削除 | 即座に制限を削除し、NORMAL に復帰 |
| レンジの追加 / 削除 | ホワイトリストと全状態を同期。削除レンジの制限・状態・ウィンドウを清掃 |
| `network.bridge`、`collector.refresh_interval_ms`、`map_max_entries`、`swl_map_max_entries` | **ホットリロード不可** — 拒否して再起動を促す |
| 不正な設定 | リロード全体を拒否。最後に成功した設定を維持し、UI 上部バーに FAILED と理由を表示 |

## 運用

### 制限の確認と解除

- **UI**：概要ページの `Limited` 列がレンジごとの制限中フロー数を表示。詳細ページは
  フローごとに `NORMAL`/`LIMITED` と残り秒数を表示。
- **ログ**：`journalctl -u vm-bandwidth-monitor | grep -iE "limited|trigger|expire"`
- **データプレーンの証拠**（最も確実）：`bpftool map dump name LIMIT_POLICIES` と
  `... LIMIT_STATE` の両方が `[]` なら、有効な制限はどこにもありません。

解除方法：レンジの `[ip_ranges.policy]` ブロックを削除（リロードで全フロー回復）、
オーバーライドで制限値を引き上げ、`limit_duration` を短縮（即時解除の可能性あり）、
再起動（全ウィンドウと状態をクリア）、または自動回復を待つだけ。解除は次の
パケットから有効です。ウィンドウは再蓄積され、トラフィックがなお超えていれば
再アームします。

### ターミナル UI（--ui）

概要ページは各レンジのリアルタイム／累計 RX/TX、観測 IP 数、制限フロー数を一覧表示。
上部バーはブリッジ、TAP 数、設定 generation、最後のリロード状態を表示。`Enter` で
IP 詳細ページへ（リアルタイムレート、ウィンドウ平均、有効なポリシー、状態、残り時間）。
トレンド画面（単一 IP またはレンジ全体）は 1h/24h/7d/30d をカバーし、帯域幅／
パケット数を切り替え可能。カラム構成はターミナル幅に自動適応します。

| キー | ページ | 機能 |
| --- | --- | --- |
| `↑`/`↓`、`Enter`、`Esc` | 全体 | ナビゲーション |
| `t` | 概要/詳細 | レンジトレンド |
| `Enter` | 詳細 | 選択中 IP のトレンド（metrics 有効化が必要） |
| `s` | 詳細 | ソート切替（IP → RX → TX → 合計） |
| `←`/`→` または `1`–`4` | トレンド | ウィンドウ切替 |
| `b` / `p` | トレンド | 帯域幅 / パケット数 |
| `r` | 概要/詳細 | 今すぐ更新 |
| `q` | 概要/詳細 | 終了 |

### 履歴トレンド（VictoriaMetrics）

```bash
cd dist && docker compose up -d     # シングルノード、127.0.0.1:8428、35 日保持
```

次に `[metrics] enabled = true` を設定（ホットリロード対応）。データモデル：各 IP に
4 つの累計カウンタ（`vmbw_{rx,tx}_{bytes,packets}_total`、ラベル `ip`/`range`）。
制限中のフローには 8 つの判定カウンタ
（`vmbw_policer_{rx,tx}_{passed,dropped}_{bytes,packets}_total` — 実際に通過/破棄された量）。
さらにプロセスレベルの運用カウンタ 4 つ（`vmbw_tap_attach_failures_total`、
`vmbw_metrics_push_{successes,failures,skipped}_total`）。デーモン再起動による
カウンタのリセットは標準の `rate()` セマンティクスで処理されます。

## 設計メモ

- **単一の eBPF オブジェクトを全 TAP に装着**：読み込みは一度だけ
  （バリデータも一度のみ）。同じプログラムを TCX（カーネル ≥ 6.6）または
  netlink clsact 経由で各 TAP に装着。7 つの map（LPM ホワイトリスト、
  IPv4/IPv6 カウンタ、ポリシー、状態、SWL ログ、ポリサー統計）は構造的に共有。
- **VLAN/QinQ**：最大 2 層の 802.1Q/802.1ad タグ（コンパイル時上限）を剥がして
  内側の IPv4/IPv6 で同一のカウント・制限パイプラインへ。3 層以上、途中切れタグ、
  非 IP ペイロードは fail-open。
- **IPv6 はアドレスでなく TAP をキーに集計** — プライバシーアドレスのローテーションで
  カウンタ map は枯渇しません。
- 装着の所有は厳密：本プログラムが作成した TC filter のみ削除。共有 qdisc は
  絶対に削除しません。装着失敗は指数バックオフで再試行。
- カウンタは単調累計値。ユーザ空間は隣接サンプルの差分からレートを計算。
  ラップ/リセット/TAP 再作成の期間は 0 とみなし、負の帯域幅も誤トリガも起きません。
- アイドルキーの回収：約 5 分間変化のないカウントキーは除去され、トラフィックが
  戻るとデータプレーンが最初のパケットで再生成します。
- 単一のエンジンタスクが全可変状態を所有。IPC/監視/シグナルは有界チャネルで通信
  （書き手は単一、共有可変ロックなし）。
- ロックファイルで二重起動を防止。IPC socket は 0600 で作成。

## 既知の制限

- IPv6 は集計のみ（制限なし、IP ごとの拆分なし）。ARP/非 IP トラフィックは
  カウントせず、ポート/接続/ペイロードは一切解析しません。
- 65535 バイトを超えるフレーム（GSO 集約フレームなど）はポリサーの対象外
  （通過し、`oversized` 観測カウンタに計上）。
- `map_max_entries` が尽きると、新しいフローはカウントされず、新しいポリシーは
  インストールできません（パケットは通過、ログに記録）。
- 累計トラフィックはデーモン起動時からの集計（再起動で map を再構築）。
- 適用は policing：超過パケットはドロップされ、バッファリングやシェーピングは
  行いません。

## ライセンス

本プロジェクトはコンポーネントごとのデュアルライセンスです：

- **ユーザ空間クレート**（`vm-bandwidth`、`vm-bandwidth-core`、`vm-bandwidth-common`）— [MIT](LICENSE)
- **eBPF プログラム**（`vm-bandwidth-ebpf`）— [GPL-2.0-only](vm-bandwidth-ebpf/LICENSE)。
  GPL-only のカーネルヘルパー（`bpf_spin_lock`）を使用しており、Linux カーネルは
  そのようなヘルパーを呼び出すプログラムに GPL 互換ライセンスを要求するためです。

## ドキュメント

- [docs/development.md](docs/development.md) — 開発ワークフローと CI ゲート
- [docs/kernel-validation.md](docs/kernel-validation.md) — 使い捨てのカーネル/データプレーン検証手順書
- [docs/production-validation.md](docs/production-validation.md) — 本番検証記録
- [docs/release.sh](docs/release.sh) — リリースヘルパー（changelog → tag → ビルド → 公開）
- [examples/](examples/) — アルゴリズムごとの動作するレート制限設定例
