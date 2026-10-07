# Spec: px 上流 Digest 認証の放置後 401 調査環境

## 背景

px を上流プロキシ（Digest 認証）の前段に置いて使うと、長時間放置した後に 401 が返り、繋がらなくなる。
周期は数十分以上で、使い続けている間は起きない。
px の client_auth（クライアント→px の認証）は使っていないので、px 自身の 120 秒 nonce 失効は対象外である。

## 目的

Agent が人手を介さずに「設定を変える → 放置する → リクエストを送る → ログを集める」を繰り返し、原因を特定できる環境を作る。
特定後は、同じ環境を修正の回帰確認に使う。

## 構成

ssh で入れる Docker ホスト（`PXLAB_HOST`）の Docker Compose で、次のコンテナを 1 つのネットワークに置く。

| サービス | 役割 |
|---|---|
| `squid` | 上流プロキシ。`digest_file_auth` で Digest 認証を要求する。nonce 関連の設定を環境変数で差し替えられる |
| `origin` | 宛先の HTTP サーバー。常に 200 を返す |
| `px` | 調査対象。ローカルのソースツリーからビルドし、`--auth=DIGEST` で `squid` に中継する |
| `capture` | `px` のネットワーク名前空間で tcpdump を回し、px↔squid 間の平文 HTTP を pcap に保存する |

クライアント（curl）は Agent が `docker compose exec` で `px` コンテナ内から、または別コンテナから実行する。

## 時間の圧縮

本番の周期（数十分〜数時間）は squid の nonce 寿命や認証キャッシュに由来する可能性が高い。
調査環境では次の値を数十秒〜数分に縮めて、同じ状態遷移を短時間で起こす。

- `nonce_garbage_interval`
- `nonce_max_duration`
- `nonce_max_count`
- `nonce_strictness` / `check_nonce_count`
- `credentialsttl`（ACL 側の認証キャッシュ）
- px の `--idle`、squid の `client_persistent_connections` / `pconn_timeout`（keep-alive 接続の寿命）

## Agent 用 CLI（`pxlab`）

Agent はこの CLI だけで操作できるようにする。出力は機械可読（JSON / JSONL）を基本にする。

| コマンド | 内容 |
|---|---|
| `pxlab up [--squid KEY=VAL ...] [--px KEY=VAL ...]` | 設定を書き出して環境を起動する。既に起動していれば作り直す |
| `pxlab down` | 環境を止める |
| `pxlab probe [--url URL] [--via px\|squid]` | 1 リクエストを送り、ステータス・所要時間・その時間帯の px ログ / squid access.log / cache.log の抜粋を JSON で返す |
| `pxlab soak --idle SEC --rounds N` | 「放置 → probe」を N 回繰り返し、結果を JSONL に追記する。401/407 を検出したら止める（`--keep-going` で継続） |
| `pxlab collect` | ログと pcap を `runs/<timestamp>/` に回収する |
| `pxlab status` | 各コンテナの状態と、現在の設定値を JSON で返す |

## px 側のデバッグコード

環境変数 `PX_DEBUG_AUTH=1` の時だけ有効にする。無効時は既存の挙動とログを変えない。

- 上流向け curl ハンドルの生成・再利用・破棄（どの接続に紐づくか）
- 認証設定（`set_curl_auth`）の呼び出しと auth 種別
- 上流からの応答コードと `Proxy-Authenticate` ヘッダー（`stale=` の有無）
- 上流へ送った `Proxy-Authorization` の nonce / nc（パスワード由来の値は伏せる）
- クライアントへ返した最終ステータス
- 必要に応じて libcurl の verbose 出力

## 完了条件

1. `pxlab up` → `pxlab probe` で、px 経由・Digest 認証ありのリクエストが 200 になる
2. `pxlab soak` で放置とリクエストを繰り返し、結果が JSONL に残る
3. 401（または 407）が起きた時に、その前後の px ログ・squid ログ・pcap が 1 か所に回収される
4. `PX_DEBUG_AUTH` 未設定時に既存テストが通る
5. Agent 向けの手順が `README.md` にあり、別セッションの Agent がそれだけで調査を始められる

## 範囲外

- 本番環境の上流プロキシ製品そのものの再現（まず squid で再現を試み、再現しなければ設定を広げる）
- px の client_auth 経路
- Windows 固有の SSPI 経路
