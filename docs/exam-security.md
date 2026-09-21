# 考試登入與提交安全

預設啟用 `EXAM_MODE=true`、`COOKIE_SECURE=true`，關閉公開註冊與明文 HTTP API。這次升級包含資料庫新增欄位與更嚴格的 Session 檢查，請在考試前部署並驗證，不要在考試進行中切換。

## 上線設定

1. 保留原本的 `DEVICE_SECRET`、資料庫與代理設定，備份資料庫。更新 `.env`：

   ```dotenv
   EXAM_MODE=true
   REGISTRATION_ENABLED=false
   COOKIE_SECURE=true
   ALLOW_INSECURE_HTTP=false
   ```

2. 取得所有考試電腦信任、且 SAN 符合 OJ 網域或 IP 的 TLS 憑證。修改 `deploy/nginx/oj.conf` 的 `server_name`、前端 `root`、`ssl_certificate`、`ssl_certificate_key` 路徑。可使用校內 CA，但必須事先將 CA 部署至受管理的考試電腦。範例不包含憑證或私鑰，沒有憑證時 Nginx 會拒絕啟動。
3. 前端執行 `npm ci && npm run build`。將 Nginx 範例安裝至實際設定目錄，先執行 `nginx -t`，再重新載入 Nginx。80 埠只轉向 HTTPS，不提供題目或代理 API；443 提供前端與 `/api/` 並設定 HSTS。首次使用也必須直接分享 **HTTPS** 網址：重新導向無法保護已經送出到 HTTP 的密碼。
4. 僅將實際代理的精確來源 IP 納入 `TRUSTED_PROXY_CIDRS`。保持後端 `127.0.0.1:8000` 及 Uvicorn `--no-proxy-headers`。Nginx 必須覆寫 `X-Real-IP`、`X-Forwarded-For`、`X-Forwarded-Proto`。不可信來源的轉送標頭無效。
5. 執行 `docker compose up -d --build backend`。啟動時自動做可重複的新增欄位遷移，舊提交來源為 `NULL`，不會捏造歷史來源。缺少來源綁定的舊 Session 需要重新登入；既有仍有效的異地登入限制會轉成帳號層級封鎖。
6. 從兩台考試電腦驗證 HTTPS、登入、題目、提交與登入事件中的 IP。考試模式要求代理能看到每台電腦的獨立來源 IP；建議使用 DHCP 保留位址。確認沒有所有登入都被記成代理／Docker gateway IP。

Compose 本身不安裝主機 Nginx 或憑證；更新程式碼／合併 PR 也不等於已完成上述部署。

## 登入規則與限制

- `/register` 預設拒絕。考試模式下即使 `REGISTRATION_ENABLED=true` 仍拒絕。考前建立帳號可由受信任管理者在後端執行：

  ```sh
  docker compose exec backend python -c 'from getpass import getpass; from database import create_user; print(create_user(input("Username: ").strip(), getpass("Password: "))["username"])'
  ```

- 非考試模式只有明確設定 `EXAM_MODE=false`、`REGISTRATION_ENABLED=true` 才能公開註冊。註冊與登入共用來源檢查及事件記錄；若新帳號建立後遭來源衝突拒絕，帳號仍存在，但不會取得 Session。
- 每次密碼驗證成功的登入嘗試都新增 `login_events`，包含被拒絕的嘗試。`outcome` 保存原因；`device_name` 是每次登入的顯示提示，不會回寫舊事件。
- Session 綁定登入時的 IP、已驗證裝置 Cookie UUID 與指紋摘要。題目、Session 恢復、紀錄、提交都檢查**當前請求**。Cookie 遺失、無效或來源變動會拒絕存取。
- 三小時內同帳號來源變動，或多帳號共用裝置，會封鎖所有相關帳號三小時並永久撤銷其現有 Session。考試模式另限制同一來源 IP 三小時內只能使用一個帳號，因此清 Cookie 與改指紋無法略過該 IP 限制。
- 來源一致不代表實體電腦一致。若裝置 Cookie、Session、指紋及伺服器看到的 IP 全部一致，一般瀏覽器無法辨別完整複製。共用 NAT、多使用者代理、IP 更換和瀏覽器更新也可能造成誤判。關閉考試模式可取消「只憑相同 IP 的跨帳號」限制，但同時失去這項防護；不要為了共用 NAT 宣稱仍具有可靠的機器綁定。
- 主機名稱、指紋、HMAC Cookie 都不是不可搬移的憑證。可靠綁定需另行設計受管理裝置憑證、受管理考試客戶端，或合適的硬體驗證器／WebAuthn 機制；可同步的 passkey 本身也不等於綁定單一電腦。本次未實作這些機制。
- 封鎖期間重新嘗試衝突登入可能延長窗口。監考人員應先處理來源衝突，等待三小時窗口結束後重新登入；撤銷的 Token 永不恢復。不要刪除稽核事件來解除限制。

## 稽核與並行處理

`submissions` 新增 `ip_address`、`device_id`、`session_hash`、`browser_fingerprint`。`session_hash` 是 SHA-256 摘要，不保存可直接登入的 Session Token。`submission_audit` 保存進入提交處理的請求、接受／拒絕／錯誤狀態及提交 ID，包括未登入、來源衝突、無效題號、缺少必填表單欄位和限流；無效裝置 Cookie 記為空 UUID。`security_events` 保存衝突原因及受影響帳號。這些來源欄位只供管理者查詢，不經一般使用者的歷史 API 回傳。

登入決策、Session 撤銷與核准共用 MariaDB 具名鎖及交易，防止多 worker 同時接受衝突登入。判題不持有鎖；寫入結果前會再次檢查 Session，並在同一交易保存結果，因此判題途中發生衝突不會新增成功提交。鎖逾時或資料庫失敗時不核准登入或提交。

先前已核准、保存的提交仍保留供稽核；後來的衝突不回溯刪除紀錄。若程序中途終止，稽核列可能停在 `received`，管理者應將這類未完成列視為未確定結果。稽核資料包含 IP 與程式碼，應限制資料庫存取並制定保存期限。

## 本機開發

只有不含真實考試密碼／資料、只綁定 loopback 的開發環境，才可明確設定 `ALLOW_INSECURE_HTTP=true`、`COOKIE_SECURE=false`。只改 Cookie 設定不足以停用 HTTPS 檢查；正式環境應維持兩項安全預設。

## 隔離回歸測試

在 repository 根目錄，先準備 `onlineoj-backend:latest` 與 `onlineoj-sandbox:latest` 映像，並建置前端。測試 override 建立獨立 tmpfs MariaDB、Nginx 與 Docker socket proxy，僅發布 loopback 18000、18080、18443。確認子網 `172.29.247.0/24` 可使用。

```sh
mkdir -p work/test-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout work/test-tls/privkey.pem -out work/test-tls/fullchain.pem \
  -subj /CN=nginx -addext subjectAltName=DNS:nginx,DNS:localhost,IP:127.0.0.1
export DEVICE_SECRET="$(openssl rand -hex 32)"
docker compose -p oj-security-fix -f docker-compose.yml -f deploy/integration/compose.yml up -d --build backend nginx
docker compose -p oj-security-fix -f docker-compose.yml -f deploy/integration/compose.yml exec -T backend python -m pytest tests -q
docker compose -p oj-security-fix -f docker-compose.yml -f deploy/integration/compose.yml exec -T backend python tests/integration_workflow.py
docker compose -p oj-security-fix -f docker-compose.yml -f deploy/integration/compose.yml exec -T backend python tests/integration_device_names.py
docker compose -p oj-security-fix -f docker-compose.yml -f deploy/integration/compose.yml down --volumes
unset DEVICE_SECRET
```

資料庫測試需同時設定 `OJ_INTEGRATION_TEST=1` 與 `MARIADB_HOST=db`；它們會清理隔離測試資料庫，絕對不要指向正式資料庫。HTTPS 流程會信任測試憑證並驗證主機名，沒有略過憑證驗證。純單元測試可安裝 `backend/requirements-test.txt` 後執行 pytest；未開啟隔離環境時會跳過需要 MariaDB 的案例。
