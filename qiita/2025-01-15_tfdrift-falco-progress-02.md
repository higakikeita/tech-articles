# 【開発日記 #2】管理外リソース自動検出 & terraform import 自動実行機能を実装！

## はじめに

こんにちは、[@keitah0322](https://x.com/keitah0322)です。

**TFDrift-Falco**の開発進捗、第2弾です。今回は **Terraformで管理されていないリソースを自動検出し、承認フローを経てterraform importを自動実行する機能** を実装しました。

**🛰️ TFDrift-Falco**
https://github.com/higakikeita/tfdrift-falco

前回（[開発日記 #1](https://qiita.com/keitah0322/items/xxxxx)）では、AWS実環境でドリフト検知に成功しました。今回はさらに一歩進めて、**管理外リソースをTerraform管理下に自動的に取り込む仕組み** を作りました。

---

## 📊 今回実装した機能

### 1. 管理外リソース自動検出 ✅

Falcoからのイベントを受信した際、Terraform Stateと照合して **管理されていないリソースを検出** します。

#### 動作フロー

```
1. Falco CloudTrailイベント受信
   ↓
2. Terraform Stateでリソース検索 (O(1) ハッシュマップ)
   ↓
3. 存在しない → 管理外リソース！
   ↓
4. terraform import コマンド自動生成
   ↓
5. コンソール表示 or 自動実行
```

#### 実装詳細

**pkg/detector/detector.go:155-165**
```go
func (d *Detector) handleEvent(event types.Event) {
    // Terraform Stateでリソース検索
    resource, exists := d.stateManager.GetResource(event.ResourceID)
    if !exists {
        log.Warnf("Resource %s not found in Terraform state (unmanaged resource)",
                  event.ResourceID)

        // 管理外リソースアラート送信
        d.sendUnmanagedResourceAlert(&event)

        // Auto-import処理（有効な場合）
        if d.cfg.AutoImport.Enabled {
            d.handleAutoImport(context.Background(), &event)
        }
        return
    }
    // ... ドリフト検知処理 ...
}
```

#### 出力例（表示のみモード）

```
⚠️  UNMANAGED RESOURCE DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Resource:
   Type: aws_iam_role
   ID:   production-api-role

📅 Event: CreateRole
⏰ Timestamp: 2025-01-15T14:23:45Z

👤 Created By:
   User:      john.doe@company.com
   ARN:       arn:aws:iam::123456789012:user/john.doe
   Account:   123456789012

💡 Recommendation:
   This resource is not managed by Terraform.
   Consider importing it:
   terraform import aws_iam_role.production_api_role production-api-role
```

**WHO（誰が）、WHEN（いつ）、WHAT（何を）** が一目で分かります。

**コミット:**
https://github.com/higakikeita/tfdrift-falco/commit/71d0e7b

---

### 2. terraform import 自動実行機能 🎉

管理外リソースを検出したら、自動的に `terraform import` を実行できます。

#### 3つの動作モード

| モード | 設定 | 安全性 | 用途 |
|--------|------|--------|------|
| **表示のみ** | `enabled: false` | ⭐⭐⭐⭐⭐ | 本番環境 |
| **手動承認** | `enabled: true`<br>`require_approval: true` | ⭐⭐⭐⭐⭐ | 推奨 |
| **自動承認（ホワイトリスト）** | `enabled: true`<br>`allowed_resources: [...]` | ⭐⭐⭐⭐ | 開発環境 |

#### モード1: 表示のみ（デフォルト）

**config.yaml:**
```yaml
auto_import:
  enabled: false  # Import コマンドを表示するだけ
```

**動作:**
- 管理外リソースを検出
- `terraform import` コマンドを表示
- 実行はしない（安全）

#### モード2: 手動承認（推奨）

**config.yaml:**
```yaml
auto_import:
  enabled: true
  require_approval: true  # 承認必須
  terraform_dir: "./infrastructure"
  output_dir: "./infrastructure/imported"
  allowed_resources:
    - "aws_iam_role"
    - "aws_iam_policy"
    - "aws_s3_bucket"
```

**実行:**
```bash
tfdrift --config config.yaml --interactive
```

**インタラクティブフロー:**
```
🔔 IMPORT APPROVAL REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Resource Type: aws_iam_role
🆔 Resource ID:   production-api-role
📝 Resource Name: production_api_role (auto-generated)
👤 Detected By:   john.doe@company.com (arn:aws:iam::123456789012:user/john.doe)
🕐 Detected At:   2025-01-15T14:23:45Z

🔄 Changes:
   role_name: production-api-role
   assume_role_policy: {
     "Version": "2012-10-17",
     "Statement": [...]
   }

💻 Import Command:
   terraform import aws_iam_role.production_api_role production-api-role

❓ Approve this import? [y/N]: y
✅ Import approved!
🚀 Executing: terraform import aws_iam_role.production_api_role production-api-role
✅ Import successful!

📄 Generated Terraform code:
resource "aws_iam_role" "production_api_role" {
  name = "production-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  # TODO: Review and adjust the following attributes
  # tags = {}
}

💡 Save this to: ./infrastructure/imported/aws_iam_role_production_api_role.tf
```

**特徴:**
- y/nで承認・却下を選択
- Import実行前に内容を確認できる
- `.tf`ファイルのコードも自動生成

#### モード3: 自動承認（ホワイトリスト）

**config.yaml:**
```yaml
auto_import:
  enabled: true
  require_approval: false  # 承認不要
  allowed_resources:       # ホワイトリスト
    - "aws_iam_role"
    - "aws_iam_policy"
```

**動作:**
- `allowed_resources` リストのリソースのみ自動Import
- リストにないリソースはスキップ（表示のみ）
- 承認プロンプトなし

**実行:**
```bash
tfdrift --config config.yaml
```

**ログ出力:**
```
INFO Auto-import feature enabled
INFO Approval workflow: AUTO (whitelist: [aws_iam_role aws_iam_policy])
INFO Auto-approving import for aws_iam_role (allowed resource type)
INFO Successfully imported production-api-role
```

**コミット:**
https://github.com/higakikeita/tfdrift-falco/commit/4ab6711

---

### 3. リソース名の自動サニタイズ

AWSリソースIDをTerraformリソース名に変換する処理を実装。

**pkg/terraform/importer.go:49-66**
```go
func (i *Importer) generateResourceName(resourceID string) string {
    // 特殊文字をアンダースコアに変換
    name := strings.ReplaceAll(resourceID, "-", "_")
    name = strings.ReplaceAll(name, ":", "_")
    name = strings.ReplaceAll(name, "/", "_")
    name = strings.ReplaceAll(name, ".", "_")

    // 先頭が数字の場合は r_ を追加
    if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
        name = "r_" + name
    }

    // 長すぎる場合は切り詰め
    if len(name) > 64 {
        name = name[:64]
    }

    return name
}
```

**変換例:**
```
production-api-role     → production_api_role
arn:aws:s3:::my-bucket  → arn_aws_s3___my_bucket
123-invalid-start       → r_123_invalid_start
```

---

### 4. 承認ワークフロー管理

**pkg/terraform/approval.go** で承認フローを管理：

```go
type ApprovalRequest struct {
    ID            string
    ResourceType  string
    ResourceID    string
    ResourceName  string
    DetectedAt    time.Time
    UserIdentity  string
    Changes       map[string]interface{}
    ImportCommand *ImportCommand
    Status        ApprovalStatus  // pending/approved/rejected/expired
    ApprovedBy    string
    ApprovedAt    time.Time
}
```

**機能:**
- 承認リクエストの生成・管理
- インタラクティブプロンプト表示
- ホワイトリストベースの自動承認
- 期限切れリクエストのクリーンアップ

**コミット:**
https://github.com/higakikeita/tfdrift-falco/commit/4ab6711

---

### 5. CLIコマンド拡張

#### `--interactive` フラグ

```bash
tfdrift --config config.yaml --interactive
```

手動承認モードで起動。y/nで承認・却下を選択できます。

#### `approval` サブコマンド

将来的な拡張のために準備（現在は`--interactive`モードを推奨）：

```bash
# 保留中の承認リクエスト一覧
tfdrift approval list

# 特定のリクエストを承認
tfdrift approval approve <request-id>

# 特定のリクエストを却下
tfdrift approval reject <request-id> --reason "Not needed"

# 期限切れリクエストをクリーンアップ
tfdrift approval cleanup --older-than 24h
```

**コミット:**
https://github.com/higakikeita/tfdrift-falco/commit/a12276a

---

## 🔧 実装のポイント

### 1. O(1)リソース検索

**pkg/terraform/state_manager.go** でStateをハッシュマップにインデックス化：

```go
type StateManager struct {
    resources map[string]*Resource  // resourceID → Resource
    // ...
}

func (sm *StateManager) GetResource(resourceID string) (*Resource, bool) {
    resource, exists := sm.resources[resourceID]
    return resource, exists
}
```

大量のリソースがあっても高速検索可能。

### 2. Detector への統合

**pkg/detector/detector.go** でImporter/ApprovalManagerを統合：

```go
type Detector struct {
    cfg             *config.Config
    stateManager    *terraform.StateManager
    importer        *terraform.Importer
    approvalManager *terraform.ApprovalManager
    // ...
}
```

設定ファイルに応じて自動初期化：

```go
if cfg.AutoImport.Enabled {
    importer = terraform.NewImporter(cfg.AutoImport.TerraformDir, cfg.DryRun)
    approvalManager = terraform.NewApprovalManager(importer, cfg.AutoImport.RequireApproval)

    if cfg.AutoImport.RequireApproval {
        log.Info("Approval workflow: MANUAL (interactive prompts)")
    } else if len(cfg.AutoImport.AllowedResources) > 0 {
        log.Infof("Approval workflow: AUTO (whitelist: %v)", cfg.AutoImport.AllowedResources)
    }
}
```

### 3. エラーハンドリング

Import失敗時も適切にエラー表示：

```go
if err := d.importer.Execute(ctx, cmd); err != nil {
    result.Error = err
    fmt.Printf("❌ Import failed: %v\n", err)
    log.Errorf("Import failed for %s: %s", event.ResourceID, result.Error)
    return
}
```

---

## 📖 ドキュメント整備

### USAGE.md

包括的な使い方ガイドを作成：

- 3つの動作モードの詳細説明
- CLIコマンドとフラグ
- 設定ファイル例
- ベストプラクティス
- トラブルシューティング

**docs/USAGE.md:**
https://github.com/higakikeita/tfdrift-falco/blob/main/docs/USAGE.md

### auto-import-guide.md

Auto-Import機能の詳細ガイド（318行）：

- 機能概要とワークフロー
- セキュリティベストプラクティス
- API統合（Webhook）
- インタラクティブモード
- トラブルシューティング

**docs/auto-import-guide.md:**
https://github.com/higakikeita/tfdrift-falco/blob/main/docs/auto-import-guide.md

---

## 🎯 ベストプラクティス

### ✅ 推奨設定

#### 本番環境
```yaml
auto_import:
  enabled: false  # 表示のみ（最も安全）
```

#### ステージング環境
```yaml
auto_import:
  enabled: true
  require_approval: true  # 手動承認
  allowed_resources:
    - "aws_iam_role"
    - "aws_iam_policy"
```

#### 開発環境
```yaml
auto_import:
  enabled: true
  require_approval: false  # 自動承認
  allowed_resources:
    - "aws_iam_role"
    - "aws_iam_policy"
    - "aws_s3_bucket"
```

### ❌ 避けるべき設定

```yaml
# 危険！全リソースを自動Import
auto_import:
  enabled: true
  require_approval: false
  allowed_resources: []  # 空 = 全て許可
```

---

## 🚀 次の開発予定

### 短期（1-2週間）
- [ ] AWS実環境でのAuto-Import動作テスト
- [ ] Terraform State更新後の自動リロード
- [ ] Import失敗時のリトライ機構

### 中期（1ヶ月）
- [ ] 複数リソースの一括Import
- [ ] Webhook統合（Slack承認ボタン）
- [ ] Prometheus メトリクス（Import成功率、レイテンシ）

### 長期（3ヶ月）
- [ ] GCP/Azure対応
- [ ] Terraform Cloud統合
- [ ] カスタムリソース名テンプレート

---

## 📊 今回の変更統計

```bash
git diff --stat 71d0e7b..a12276a
```

**追加:**
- `pkg/detector/detector.go`: +67行（Auto-Import統合）
- `cmd/tfdrift/main.go`: +97行（CLIコマンド追加）
- `docs/USAGE.md`: +357行（新規作成）

**合計:** +521行

**コミット履歴:**
- https://github.com/higakikeita/tfdrift-falco/commit/4ab6711
- https://github.com/higakikeita/tfdrift-falco/commit/a12276a

---

## まとめ

今回実装した **管理外リソース自動検出 & terraform import自動実行機能** により、以下が可能になりました：

✅ Terraformで管理されていないリソースを即座に検出
✅ terraform importコマンドを自動生成
✅ 承認フローを経て安全に自動Import
✅ .tfファイルのコードも自動生成
✅ 3つの動作モード（表示のみ / 手動承認 / 自動承認）

**TFDrift-Falco は「検知」だけでなく「自動修復」までカバーするツールになりました。**

次回は **AWS実環境でのAuto-Import動作テスト** を実施し、実際の運用で得られた知見を共有します。

---

## リンク

- **GitHub:** https://github.com/higakikeita/tfdrift-falco
- **前回記事:** [開発日記 #1 - AWS実環境でドリフト検知に成功！](https://qiita.com/keitah0322/items/xxxxx)
- **技術記事（Zenn）:** [Falco×TerraformでリアルタイムIaCドリフト検知](https://zenn.dev/keitah/articles/xxxxx)

フィードバック・質問・コントリビュート、お待ちしています！🙌

**Twitter:** [@keitah0322](https://x.com/keitah0322)
