# Falco × Platform Engineering — 設計と観測の統合

> **本記事は3部構成のシリーズ第3回です。**
> - 第1回：[Platform Engineeringとは何か？ — Declarativeの限界]
> - 第2回：[Runtime Securityとは何か？・eBPFの仕組み]
> - 第3回：Falco × Platform Engineering の統合（本記事）

---

## これまでの流れ

第1回では、Platform Engineering の強みとその限界を確認した。

> **IaC は「設計の正しさ」を保証するが、「実行時の安全性」は保証しない。**

第2回では、その限界を補う技術として Runtime Security と eBPF を学んだ。

> **eBPF により、カーネルレベルで全コンテナの syscall をリアルタイム観測できる。**

では、その eBPF を基盤として実際に動く Runtime Security エンジンが **Falco** だ。

---

## Falco とは何か？

**Falco** は、CNCF（Cloud Native Computing Foundation）がホストするオープンソースの Runtime Security エンジンだ。

- eBPF（または カーネルモジュール）でシステムコールを収集
- 独自のルールエンジンで異常を検知
- アラートをリアルタイムで出力

```mermaid
graph LR
    A[Linux Kernel\n syscall] -->|eBPF / kernel module| B[Falco エンジン]
    B --> C[ルールと照合]
    C -->|一致| D[🚨 アラート出力]
    C -->|不一致| E[✅ スルー]
    D --> F[stdout / syslog\nSlack / PagerDuty\nSIEM ...]
```

---

## Falco のルールエンジン

Falco の中核は**ルール（Rules）**だ。YAML 形式で記述し、「何を検知するか」を宣言する。

```yaml
- rule: Shell spawned in a container
  desc: コンテナ内でシェルが起動された
  condition: >
    spawned_process
    and container
    and proc.name in (shell_binaries)
  output: >
    シェルが起動されました
    (user=%user.name container=%container.name
     shell=%proc.name parent=%proc.pname)
  priority: WARNING
```

ルールは3つの要素で構成される。

| 要素 | 役割 | 例 |
|------|------|-----|
| `condition` | 検知条件（フィルタ式） | `コンテナ内でシェルが起動された` |
| `output` | アラートのメッセージ形式 | ユーザ名・コンテナ名・プロセス名など |
| `priority` | 重大度 | `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL` |

---

## Falco が検知できる脅威の例

Falco はデフォルトルールセットで、広範囲の攻撃パターンを検知できる。

```mermaid
graph LR
    ROOT((Falco\n検知パターン))

    ROOT --> PROC[プロセス系]
    PROC --> PROC1[コンテナ内でのシェル起動]
    PROC --> PROC2[不審な実行ファイルの呼び出し]
    PROC --> PROC3[特権プロセスの起動]

    ROOT --> FILE[ファイル系]
    FILE --> FILE1["/etc/passwd への書き込み"]
    FILE --> FILE2[機密ファイルへのアクセス]
    FILE --> FILE3[バイナリの改ざん]

    ROOT --> NET[ネットワーク系]
    NET --> NET1[予期しない外部通信]
    NET --> NET2[非標準ポートへの接続]
    NET --> NET3[コンテナからのスキャン]

    ROOT --> PRIV[権限系]
    PRIV --> PRIV1[setuid による権限昇格]
    PRIV --> PRIV2[ホスト namespace アクセス]
    PRIV --> PRIV3[privileged コンテナの不審な操作]
```

### 具体的なシナリオ：侵害されたコンテナの検知

```mermaid
sequenceDiagram
    participant Attacker as 攻撃者
    participant App as アプリコンテナ
    participant Kernel as Linux Kernel
    participant Falco as Falco
    participant Alert as アラート基盤

    Attacker->>App: 脆弱性を突いて侵入
    App->>Kernel: execve("/bin/bash")
    Kernel->>Falco: syscall イベント通知
    Falco->>Falco: ルール照合\n「コンテナ内でシェルが起動」
    Falco->>Alert: 🚨 CRITICAL アラート送信
    Alert->>Attacker: 攻撃が検知・遮断される
```

---

## Falco のアーキテクチャ（Kubernetes 環境）

Kubernetes 環境では、Falco は DaemonSet として各ノードに配置される。

```mermaid
graph TD
    subgraph Cluster [Kubernetes Cluster]
        subgraph NodeA [Node A]
            FA[Falco DaemonSet]
            CA1[Container]
            CA2[Container]
            KA[Linux Kernel]
            CA1 --> KA
            CA2 --> KA
            KA -->|eBPF| FA
        end

        subgraph NodeB [Node B]
            FB[Falco DaemonSet]
            CB1[Container]
            CB2[Container]
            KB[Linux Kernel]
            CB1 --> KB
            CB2 --> KB
            KB -->|eBPF| FB
        end

        FW[Falcosidekick\nアラートルーティング]
        FA --> FW
        FB --> FW
    end

    FW --> S1[Slack]
    FW --> S2[PagerDuty]
    FW --> S3[Elasticsearch / SIEM]
    FW --> S4[Prometheus / Grafana]
```

**Falcosidekick** はアラートの出力先を柔軟にルーティングする周辺ツールで、50以上の出力先に対応している。

---

## Platform Engineering との統合

ここが本記事の核心だ。

Falco 単体は強力な Runtime Security エンジンだが、Platform Engineering と統合することで、**設計から観測まで一気通貫のセキュリティ基盤**が完成する。

### 統合の全体像

```mermaid
graph TD
    subgraph Design [設計レイヤー Platform Engineering]
        A[IaC\nTerraform / Pulumi]
        B[Kubernetes マニフェスト\nHelm / Kustomize]
        C[セキュリティポリシー\nOPA / Kyverno]
        D[Golden Path\nIDPテンプレート]
    end

    subgraph Deploy [デプロイレイヤー CI/CD]
        E[ビルド・テスト]
        F[イメージスキャン\nTrivy / Grype]
        G[ポリシーチェック]
    end

    subgraph Runtime [実行レイヤー Runtime Security]
        H[Falco\n振る舞い検知]
        I[eBPF\nsyscall 収集]
        J[Falcosidekick\nアラートルーティング]
    end

    subgraph Respond [対応レイヤー]
        K[SIEM / ログ基盤]
        L[インシデント対応]
        M[自動遮断\nNetwork Policy 更新など]
    end

    Design -->|コードとして定義| Deploy
    Deploy -->|デプロイ| Runtime
    Runtime -->|アラート| Respond
    Respond -->|フィードバック| Design
```

---

## Golden Path にセキュリティを組み込む

Platform Engineering の「Golden Path」にFalcoを組み込むことで、開発者が意識しなくてもセキュリティ観測が有効になる。

```mermaid
sequenceDiagram
    participant Dev as 開発者
    participant IDP as Internal Developer Platform
    participant K8s as Kubernetes
    participant Falco as Falco

    Dev->>IDP: 新しいアプリをデプロイ
    IDP->>K8s: 標準テンプレートを適用
    Note over K8s: NetworkPolicy\nRBAC\nPodSecurityPolicy も自動設定
    K8s->>Falco: Falco が自動で監視開始
    Note over Falco: 開発者は何もしていない
    Note over Falco: でもランタイム観測は有効
```

> **「セキュリティは後付け」ではなく「最初から組み込まれている」**

これが Platform Engineering × Runtime Security の目指す姿だ。

---

## 実際の運用：アラートから対応まで

```mermaid
flowchart LR
    A[Falco\nアラート発生] --> B{重大度}
    B -->|INFO / DEBUG| C[ログ蓄積\n後から分析]
    B -->|WARNING| D[Slack 通知\n担当者が確認]
    B -->|ERROR / CRITICAL| E[PagerDuty\n即時対応]
    E --> F{自動対応？}
    F -->|Yes| G[Network Policy 更新\nPod 強制終了]
    F -->|No| H[インシデント対応\nチームが手動対応]
    G --> I[インシデント記録]
    H --> I
    I --> J[ポストモーテム\nルール改善]
    J --> A
```

---

## IaC × Falco：ルールもコードで管理する

重要な点として、Falco のルール自体も IaC として管理できる。

```mermaid
graph LR
    A[Falco Rules\nYAML / Git管理] -->|Helm values| B[Falco DaemonSet]
    C[CI/CD パイプライン] -->|ルール変更をテスト・デプロイ| B
    D[Security Team] -->|ルールをレビュー・マージ| A
```

Terraform でインフラを、Kubernetes マニフェストでアプリを、そして Falco ルールで「検知すべき振る舞い」を——すべてをコードとして Git で管理できる。

---

## 設計と観測の統合：最終的な全体像

3回にわたって見てきたすべてを統合すると、こうなる。

```mermaid
graph TD
    subgraph PE [Platform Engineering]
        direction LR
        A1[IaC で基盤設計]
        A2[Golden Path で標準化]
        A3[Self-Service で提供]
    end

    subgraph Gap [⚠️ 宣言的設計の限界]
        B1[実行時の振る舞いは見えない]
    end

    subgraph RS [Runtime Security]
        direction LR
        C1[eBPF で syscall 収集]
        C2[Falco でルールベース検知]
        C3[Falcosidekick でアラート配信]
    end

    subgraph Loop [継続的改善ループ]
        D1[インシデント分析]
        D2[ルール改善]
        D3[設計フィードバック]
    end

    PE -->|デプロイ| Gap
    Gap -->|補完する| RS
    RS --> Loop
    Loop --> PE
```

Platform Engineering が「**作る**」を担い、Runtime Security が「**守る**」を担う。

そしてその二つが連携することで、**継続的に改善されるセキュリティ基盤**が完成する。

---

## まとめ：シリーズ全体の結論

| 回 | テーマ | 結論 |
|----|--------|------|
| 第1回 | Platform Engineering とは | 開発者体験を最大化する基盤。ただし「設計の正しさ」しか保証しない |
| 第2回 | Declarative の限界 / eBPF | IaC では実行時が見えない。eBPF がその観測を可能にした |
| 第3回 | Falco × Platform Engineering | 設計と観測を統合することで、はじめて本当に安全な基盤が完成する |

> **「作る技術」と「守る技術」は、別物ではない。**
> **二つを統合して、はじめて現代のプラットフォームは完成する。**

---

## 参考リンク

**Falco**
- [Falco 公式ドキュメント](https://falco.org/docs/)
- [CNCF Falco プロジェクト](https://www.cncf.io/projects/falco/)
- [Falco Rules リポジトリ（GitHub）](https://github.com/falcosecurity/rules)
- [Falcosidekick — アラート出力先一覧](https://github.com/falcosecurity/falcosidekick)
- [Falco Helm Chart](https://github.com/falcosecurity/charts)

**Platform Engineering**
- [Platform Engineering — CNCF Platforms White Paper](https://tag-app-delivery.cncf.io/whitepapers/platforms/)
- [Backstage — Spotify 製 IDP フレームワーク](https://backstage.io/)
- [OPA（Open Policy Agent）— ポリシーエンジン](https://www.openpolicyagent.org/)
- [Kyverno — Kubernetes ネイティブポリシーエンジン](https://kyverno.io/)

**セキュリティ全般**
- [eBPF 公式サイト](https://ebpf.io/)
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/cloud-native-security-whitepaper.md)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
