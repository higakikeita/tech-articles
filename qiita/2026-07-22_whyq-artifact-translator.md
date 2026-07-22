# セキュリティツールの出力を「人間語」に翻訳するOSS『whyq』を作ってみた（10ツール横断）

## はじめに

こんにちは、[@keitah0322](https://x.com/keitah0322) です。

普段は Sysdig で Cloud Native Security / Runtime Security 周りを見ていて、Falco・Trivy・Terraform・Kubernetes など、セキュリティやIaCの「出力ファイル」を毎日のように眺めています。

そこでずっと感じていたのがこれです。

> スキャナは「**何が**」危ないかは教えてくれる。でも「**なぜ**危ないのか」「**まず何を確認**すればいいのか」「**次の一手**」は、結局ドキュメントを読みに行くしかない。

この「読んだ人が最初に詰まるところ」を埋める CLI を作ったので、作った話と、実際に10ツールで使ってみた話を書きます。

- GitHub: https://github.com/higakikeita/whyq
- PyPI: `pip install whyq`

## なぜ作ったか — パイプラインの真ん中が空いていた

私は自分の OSS を「**検知 → 理解 → 修復**」という一つの物語として作っています。

```
検知(detect) ──►  理解(understand)  ──►  修復(fix)
tfdrift/trivy/     ← ここが空白 →        remedify
falco/sysdig...    何が/なぜ/危険度       distro-aware な
                   /確認/修正/参考URL     修正コマンド
```

検知の道具は世の中に溢れている。修復は [remedify](https://github.com/higakikeita/remedify) という別の OSS で作りました。でも **真ん中の「理解」を担う独立した道具が無かった**。そこを埋めるのが `whyq`（ワイク）です。

## whyq とは — アーティファクト翻訳機

`whyq explain <file>` に、**すでに手元にある出力ファイル**を渡すだけ。所見ごとに6項目を返します。

```bash
$ trivy image --format json -o scan.json app:latest
$ whyq explain scan.json
```

```
■ zlib: integer overflow and resultant heap-based buffer overflow  [CRITICAL]  (CVE-2023-45853)
  何が:   zlib1g — vulnerability
  なぜ:   A known vulnerability (CVE-2023-45853) affects zlib1g, but no fix is
          published yet — mitigation, not patching, is the near-term lever.
  確認:   Confirm zlib1g is actually reachable in your runtime path (not just
          present on disk), and check whether the installed version is really in use.
  修正:   remedify <scan.json>  (OS-package remediation is remedify's job)
  参考:   https://avd.aquasec.com/nvd/cve-2023-45853
```

接続不要・クラスタ不要・SaaS不要。**手元のファイルを渡すだけ**です。

### 既存ツール（k8sgpt / HolmesGPT）との違い

「セキュリティの出力を説明する」領域は空白ではありません。ただし棲み分けがはっきりしています。

- **k8sgpt**: **ライブの Kubernetes クラスタ**を診断する。任意のファイルは食えない。
- **HolmesGPT**: アラート元に**接続して自律調査する**重めのエージェント。
- **whyq**: **ディスクにすでにあるアーティファクトを翻訳する**。クラスタも接続も要らず、**複数ツールを1つの文法で**。

なので whyq の旗は一つだけ、「**アーティファクト翻訳機・横断**」です。「軽い・SaaS不要」は k8sgpt がすでに占めている土俵なので、そこは旗印にしていません。

## 作ってみた — 設計の3つの軸

### ① 単一ファイル Python・依存ゼロ

`whyq.py` 一本、標準ライブラリのみ。`scp` 一本で持っていける、という一貫性を remedify と揃えています。

### ② 「決定的な部分」と「AI の部分」を分離する

ここが設計の肝です。6項目のうち、

- **決定的に計算する**: 何が / 危険度 / 修正コマンド / 参考URL（パース結果からそのまま導出。回帰テストで固定）
- **人間語にする**: なぜ / まず確認すること（LLM、または既定のテンプレート）

**LLM に投げるのは「なぜ / 確認」の文章化だけ**。危険度や修正コマンドは決定的なコードが計算します。「決定的な道具が計算し、AI は説明する」という分担で、監査可能性を保っています。

しかも LLM は **既定オフライン**。キーを渡さなければテンプレートで動き、**データは一切マシンの外に出ません**。使いたい人だけ `--llm anthropic` や `--llm ollama`（ローカル）を明示的に opt-in する BYO-key 方式です。人間語要約に LLM が要る以上、「SaaS不要」を無条件には名乗らない——という正直さを設計に埋めています。

### ③ 全ツールを1つの「正規化 finding」に落とす

内部では、どのツールの出力も**同じ形の finding** に正規化されます。

```
parser（ツール別）→ 正規化 finding → 出力ビルダ（6項目）
```

**新しいツールに対応する = detector と parser を1つ足すだけ**。出力パスは一切変わりません。これが「横断を後から足せる」設計です。

## 使ってみた — 10ツールを同じコマンドで

実際に各ツールの出力を食わせてみます。**どれも同じ `whyq explain` で、同じ6項目**が返ります（以下は実際の出力です）。

### Falco / Sysdig（ランタイム検知）

```
■ Terminal shell in container  [CRITICAL]  (Terminal shell in container)
  なぜ:   At runtime, Sysdig saw 'bash' do something the rule 'Terminal shell in
          container' flags as suspicious — this already happened on a live host,
          so it's a signal to investigate, not a static risk to schedule.
  確認:   Decide whether this was expected activity or an intrusion — check the
          exact command (`bash -i`), which container it ran in. Correlate with
          who/what triggered it before isolating or killing anything.
```

Falco も Sysdig Secure イベントも、内部では同じ「ランタイム検知（runtime_event）」として扱われます。ツール名が違うだけで finding は同じ形。MITRE ATT&CK タグは自動で参考URLになります。

### Terraform plan（IaC の変更）

```
■ replace aws_db_instance  [HIGH]  (aws_db_instance.main)
  なぜ:   Terraform will REPLACE aws_db_instance.main (destroy then recreate).
          Expect downtime and a new identity (IP/ID/ARN).
  確認:   Before apply: confirm nothing depends on it and its data is backed up.
          Plan for downtime and the new identity.
  修正:   Destructive — review carefully; if intended, `terraform apply`
          (consider -target or lifecycle guards to scope the blast radius).
```

`terraform show -json` を渡すと **「何が変わる・どこが危険か」** に翻訳。`delete` / `replace` は自動で HIGH に、`create` は LOW に。`resource_drift`（コード外で変わった資源）も拾います。

### AWS CloudTrail（監査ログ）

```
■ ConsoleLogin on signin.amazonaws.com  [HIGH]  (ConsoleLogin)
  なぜ:   ...root called ConsoleLogin... as the ROOT account — root activity is
          almost never routine and is a top-tier alert.
  確認:   Confirm the actor was authorized from this source IP, and tie it to a
          change ticket or known automation. If not, treat the session as compromised.
```

root の利用や `StopLogging` / `CreateAccessKey` などの破壊的・機微な API は HIGH、`AccessDenied` は MEDIUM、read-only は LOW と重み付けします。

### Kubernetes events

```
■ BackOff on Pod/web-7d9c  [HIGH]  (BackOff)
  なぜ:   Kubernetes flagged 'BackOff' on Pod/web-7d9c (7×): Back-off restarting
          failed container. A Warning means the kubelet hit a real problem.
  確認:   Inspect it: `kubectl describe pod web-7d9c -n prod` and its logs.
          A rising count means it's ongoing, not a one-off.
```

### 対応ツール一覧

| 領域 | ツール |
|---|---|
| スキャン（脆弱性） | Trivy / Grype / OSV-Scanner |
| ランタイム検知 | Falco / Sysdig Secure events |
| IaC | Terraform plan / Checkov |
| クラスタ | Kubernetes events |
| クラウド監査 | AWS CloudTrail |
| シークレット | gitleaks |

面白いのは、後から足した **gitleaks と Checkov が、新しい種類を作らずに既存の "secret" / "misconfiguration" にそのまま乗った**ことです。ツールが増えても文法が増えない——これが「1つの文法で横断」の何よりの実証になりました。

## 出力は貼れる・繋げる

人間が読む `text` に加えて、

- **`--format markdown`**: Issue / PR / Slack にそのまま貼れる形

```bash
$ whyq explain scan.json --format markdown
# whyq — 3 findings (1 CRITICAL, 2 HIGH)
## 🔴 CRITICAL — zlib: integer overflow... (`CVE-2023-45853`)
- **何が / What:** zlib1g — vulnerability (via trivy)
...
```

- **`--format json`**: 機械可読。修復ツール [remedify](https://github.com/higakikeita/remedify) がそのまま食える形。OSパッケージ脆弱性の「修正」は whyq が再実装せず remedify に委譲します（理解は whyq、修正は remedify、という自然な境界）。

- **MCP サーバ**: `whyq_mcp.py`（依存ゼロ）を使うと、AI エージェント（Claude Desktop / Code）が `explain_artifact` ツールでアーティファクトを渡し、構造化された理解を受け取れます。エージェント自身が LLM なので、whyq は「決定的な構造」を提供する担当です。

## 使い方

```bash
pip install whyq
whyq explain scan.json                    # 人間向け
whyq explain scan.json --format markdown  # 貼り付け用
whyq explain scan.json --min-severity HIGH
terraform show -json plan.tfplan | whyq explain -   # パイプもOK
```

- 依存ゼロ・標準ライブラリのみ（Python 3.9+）
- 既定オフライン（LLM を使う時だけ `--llm` で明示 opt-in）
- MIT ライセンス

## おわりに

「検知 → 理解 → 修復」の真ん中を埋める、という当初の狙いはひとまず形になりました。10ツール・6領域を1つの文法で翻訳でき、`pip install` で入り、MCP でエージェントからも呼べます。

develop in public で作っているので、続きもマイルストーンごとに書いていきます。フィードバック・Issue歓迎です。

- GitHub: https://github.com/higakikeita/whyq
- PyPI: https://pypi.org/project/whyq/
