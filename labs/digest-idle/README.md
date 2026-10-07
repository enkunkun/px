# digest-idle lab（Agent 向け手順）

px を上流プロキシ（Digest 認証）の前段に置くと、放置した後に 401 が返って戻らなくなる。
この lab は、その原因を Agent が自律的に調べるための環境である。
背景と完了条件は [SPEC.md](SPEC.md) にある。

## 構成

`PXLAB_HOST` で指定した Docker ホスト（ssh で入れるもの）の上で `squid`（Digest 認証）・`origin`（宛先）・`px`（このソースツリーからビルド）・`client`（curl）・`capture`（tcpdump）を動かす。
Mac 側からは `bin/pxlab-remote` だけを使う。
このコマンドはソースツリーを `PXLAB_HOST` の `~/pxlab-src/` に rsync してから、そこで `pxlab.py` を実行する。
px のコードを書き換えた場合も、次の `up` で再ビルドされる。

```sh
export PXLAB_HOST=<docker-host>        # ssh で入れる Docker ホスト
R=labs/digest-idle/bin/pxlab-remote   # リポジトリのルートから
```

## コマンド

| コマンド | 内容 |
|---|---|
| `$R up [--squid KEY=VAL ...] [--px KEY=VAL ...]` | 設定を書き出し、スタックを作り直す。直前の `runs/current` は `runs/<時刻>/` に退避する |
| `$R probe [--via px\|squid]` | 1 リクエストを送り、ステータスとその時間帯の px / squid のログを JSON で返す |
| `$R soak --idle 秒 --rounds N [--keep-going]` | 「放置 → probe」を繰り返す。2xx 以外で止まる |
| `$R fault --upstream-auth broken\|ok` | squid のパスワードを壊す・戻す。squid だけを再起動し、px のメモリ上の状態は保つ |
| `$R scenario latch [--failures N] [--wait 秒]` | ラッチ再現の一連の手順。再現したら終了コード 1 |
| `$R status` / `$R collect` / `$R down` | 状態の確認、ログと pcap の回収、停止 |
| `$R pull` | Docker ホストの `runs/` を手元の `labs/digest-idle/runs/` にコピーする |

`--squid` に渡せるキーは `pxlab.py` の `SQUID_DEFAULTS` にある（nonce 寿命、認証キャッシュ、keep-alive 寿命など）。
`--px KEY=VAL` は `PX_<KEY>` 環境変数として px に渡る（例: `--px idle=10`）。

## 分かっていること（2026-10-07 時点）

1. **戻らない理由は mcurl の失敗カウンタのラッチである。**
   上流の 407 が 3 回続くと、mcurl（pymcurl）は `set_proxy` で False を返し、以後は上流に問い合わせずに 401 を返す。
   カウンタを 0 に戻すのは「上流から 407 以外が返った時」だけなので、閾値を超えると px を再起動するまで戻らない。
   `scenario latch` で再現できる（上流を戻した後も px は `Authentication issues with this proxy server (failed 3 times)` で 401）。
   該当箇所は mcurl の `set_proxy`（`MCURL.failed` の判定）と、`do` の中の 407 処理（`self.failed[curl.proxy]` の加算とリセット）。
   2026-10-04 の mcurl 8.22.0 でも残っている。
2. **squid は認証済みの資格情報を `authenticate_ttl` の間保持する。**
   パスワードを変えても `squid -k reconfigure` だけでは反映されないので、`fault` は squid を再起動する。
3. **上流が健全なら、nonce や認証キャッシュが切れても失敗しない。**
   `nonce_max_duration=1 minute`、`nonce_max_count=3`、`authenticate_ttl=30 seconds`、`pconn_timeout=10 seconds` に縮め、75 秒の放置とリクエストを 6 回繰り返したところ、すべて 200 だった。
   mcurl はリクエストごとに `curl_easy_reset` で Digest の状態を捨て、毎回新しい nonce で認証し直すため、nonce の失効そのものは引き金にならない。

## 修正（`--authretry`）

px 側に `--authretry=N`（既定 0 = 無効）を足した。
ブロックされた上流プロキシに対し、最後に問い合わせてから N 秒経っていれば 1 回だけ問い合わせ直す。
成功すれば mcurl がカウンタを 0 に戻し、失敗すれば次の N 秒まで再びブロックする。
起点は「最後に問い合わせた時刻」なので、長く放置した後の最初のリクエストですぐに再試行する。

lab での確認結果（2026-10-07）:

| 条件 | 結果 |
|---|---|
| `up` → `scenario latch --wait 25`（既定値） | `latched: true`（従来どおり） |
| `up --px authretry=20` → `scenario latch --wait 25` | 上流が戻った直後から 200、`latched: false` |
| `authretry=20` で上流を壊したまま、6 本 → 21 秒待つ → 2 本 | squid が受けた Digest 送信は 4 回（閾値の 3 回と再試行 1 回）。間隔内のリクエストは上流に届かない |

## 未解明のこと

本番で何が 407 を 3 回引き起こすか（ラッチの引き金）は分かっていない。
候補と確かめ方は次のとおり。

- 上流の再起動や認証基盤（helper の裏の LDAP/AD 等）の一時的な失敗。squid は helper が ERR/BH を返すと `stale=false` の 407 を返し、libcurl は再送しない
- `authenticate_ttl` が切れた瞬間に並列リクエストが重なり、一部が 407 になる（直列の soak では起きなかった。並列 probe は未実装）
- keyring がロックされてパスワードが空になる（`PX_PASSWORD` を使っていれば該当しない）

本番の px ログ（`--debug`）に `Proxy authentication failed` と `failed 3 times` が出ているかを確かめるのが最短である。
出ていれば、最初の `Proxy authentication failed` の直前にある上流の `Proxy-Authenticate` ヘッダー（`stale=` の値）が引き金の手がかりになる。

## 調べ方の型

1. 仮説を 1 つ選び、`up --squid ...` で該当する寿命を数十秒に縮める
2. `soak --idle <寿命より少し長い秒数> --rounds N` で放置とリクエストを繰り返す
3. 2xx 以外が出たら `probe` の JSON（px_log / squid_log）を読み、`collect` → `pull` で pcap を手元に取る
4. 結果を `runs/<時刻>/` ごと残し、この README の「分かっていること」を更新する
