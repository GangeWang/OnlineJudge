# OnlineJudge 使用說明書

> 考試安全預設已更新：強制 HTTPS、關閉註冊、衝突時封鎖所有相關 Session。升級與完整测试請先閱讀 [考試安全部署說明](docs/exam-security.md)。

本專案是一個簡易版 Online Judge（OJ）系統，採用以下技術：

* **前端**：React + Vite
* **後端**：FastAPI
* **判題沙箱**：Docker 容器（限制 CPU / 記憶體 / 網路）
* **資料庫**：MariaDB（帳號與答題紀錄）

---

# 1. 專案結構

```text
OnlineJudge/
├─ front/                  # 前端專案（React + Vite）
├─ backend/                # 後端 API 與判題邏輯
│  ├─ main.py              # FastAPI 入口
│  ├─ judge.py             # 判題核心邏輯
│  ├─ database.py          # MariaDB 連線與資料操作
│  ├─ requirements.txt     # 後端套件
│  └─ problems/            # 題庫目錄（每題一個資料夾）
├─ deploy/nginx/           # 反向代理設定範例
├─ sandbox/                # 沙箱映像相關檔案
└─ docker-compose.yml      # 後端容器啟動設定
```

---

# 2. 系統需求

請先安裝以下工具：

1. **Docker**
2. **Docker Compose**（或 `docker compose`）
3. **Node.js 18+**（前端開發）
4. **Python 3.10+**（本機直接執行後端）

---

# 3. 環境變數設定（後端）

後端主要使用以下環境變數：

| 變數                 | 說明                | 預設值                       |
| ------------------ | ----------------- | ------------------------- |
| `JUDGE_IMAGE`      | 判題沙箱 Docker 映像名稱  | `onlineoj-sandbox:latest` |
| `HOST_BACKEND_DIR` | 主機上的 backend 絕對路徑 | `${PWD}/backend`          |
| `MARIADB_HOST`     | MariaDB 主機位置      | `host.docker.internal`    |
| `MARIADB_PORT`     | MariaDB 埠號        | `3306`                    |
| `MARIADB_USER`     | 資料庫使用者            | `onlinejudge`             |
| `MARIADB_PASSWORD` | 資料庫密碼             | `onlinejudge`             |
| `MARIADB_DATABASE` | 資料庫名稱             | `onlinejudge`             |
| `DEVICE_SECRET`    | 裝置 Cookie 的 HMAC 密鑰（至少 32 bytes） | **必填，無預設值** |
| `COOKIE_SECURE`    | 是否只透過 HTTPS 傳送 Cookie | `true` |
| `EXAM_MODE` | 考試模式，關閉註冊並限制同 IP 多帳號 | `true` |
| `REGISTRATION_ENABLED` | 非考試模式是否開放註冊 | `false` |
| `ALLOW_INSECURE_HTTP` | 明確允許本機開發 HTTP | `false` |
| `TRUSTED_PROXY_CIDRS` | 可提供 `X-Real-IP` 的可信代理 CIDR（逗號分隔） | `127.0.0.1/32,::1/128` |

目前 `docker-compose.yml` 內 `backend` 服務預設：

```env
HOST_BACKEND_DIR=${HOST_BACKEND_DIR:-${PWD}/backend}

MARIADB_HOST=host.docker.internal
MARIADB_PORT=3306
MARIADB_USER=onlinejudge
MARIADB_PASSWORD=onlinejudge
MARIADB_DATABASE=onlinejudge
DEVICE_SECRET=<至少 32 bytes 的隨機密鑰>
```

可使用 `openssl rand -hex 32` 產生 `DEVICE_SECRET`。請勿提交此密鑰，且所有後端實例必須使用相同值。範例 Nginx 現在需要 TLS 憑證；請依 [部署說明](docs/exam-security.md) 設定。只有隔離本機開發可同時設定 `ALLOW_INSECURE_HTTP=true` 與 `COOKIE_SECURE=false`。

> 若你的環境沒有 `PWD`，請手動設定 `HOST_BACKEND_DIR` 為實際的 backend 絕對路徑，避免判題時 Docker 掛載失敗。

---

# 4. 啟動方式

## 4.1 使用 Docker Compose 啟動後端

在專案根目錄執行：

```bash
docker compose up --build
```

啟動成功後：

```
Backend upstream (僅供可信 Nginx 連接，直接 HTTP 請求會被拒絕):
http://127.0.0.1:8000
Browser URL: https://<OJ host>
```

目前 `docker-compose.yml` 僅啟動：

* FastAPI Backend
* Docker 判題環境

不包含：

* 前端服務
* MariaDB 容器

因此 MariaDB 需要先在主機端啟動。

---

## 4.2 啟動前端（React + Vite）

進入前端資料夾：

```bash
cd front
```

安裝套件：

```bash
npm install
```

啟動開發伺服器：

```bash
npm run dev
```

開發模式下，前端會透過 Vite `/api` 代理呼叫後端，並轉發 `X-Forwarded-*` 標頭供後端辨識來源 IP。

其他可用指令：

```bash
npm run build
```

建立正式版本。

```bash
npm run preview
```

預覽正式版本。

---

## 4.3 本機啟動後端（不使用 Docker）

進入 backend：

```bash
cd backend
```

安裝 Python 套件：

```bash
pip install -r requirements.txt
```

啟動 FastAPI：

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000 --no-proxy-headers
```

目前 `requirements.txt` 包含：

* fastapi
* uvicorn
* python-multipart
* pymysql

---

# 5. MariaDB 資料庫設定

請先建立以下資料庫：

| 項目       | 設定                     |
| -------- | ---------------------- |
| Database | `onlinejudge`          |
| User     | `onlinejudge`          |
| Password | `onlinejudge`          |
| Host     | `host.docker.internal` |
| Port     | `3306`                 |

範例：

```text
MariaDB
 └─ onlinejudge
     ├─ users
     └─ submissions
```

---

## Linux 環境注意事項

Linux Docker 預設可能無法解析：

```text
host.docker.internal
```

若連線失敗，可以：

1. 改成主機實際 IP：

```env
MARIADB_HOST=192.168.x.x
```

或

2. 將 MariaDB 加入同一份 `docker-compose.yml`，改用服務名稱連線。

---

# 6. 判題流程

系統流程如下：

```
使用者
  │
  ▼
React 前端
  │
  ▼
FastAPI Backend
  │
  ▼
Judge Core
  │
  ▼
Docker Sandbox
  │
  ▼
回傳結果
  │
  ▼
MariaDB 儲存紀錄
```

判題時：

1. 使用者提交程式碼
2. Backend 接收提交內容
3. 建立隔離 Docker Container
4. 限制：

   * CPU
   * Memory
   * Network
5. 執行測資
6. 回傳判題結果
7. 寫入 MariaDB

---

# 7. 常見問題

## Q1：提交後判題找不到掛載路徑

檢查：

* `HOST_BACKEND_DIR` 是否為 backend 的絕對路徑
* Docker 是否有掛載：

```text
/var/run/docker.sock
```

---

## Q2：後端啟動但資料庫連不上

確認：

* MariaDB 是否啟動
* Host / Port 是否正確
* 帳號密碼是否一致

Linux 若使用：

```env
MARIADB_HOST=host.docker.internal
```

失敗，請改用主機 IP。

---

## Q3：前端可以開啟但 API 失敗

檢查：

1. Backend 是否啟動：

```text
http://localhost:8000
```

2. 前端 API Base URL 是否設定正確

3. 確認 CORS 設定

4. 若前端不是直連後端，而是透過代理（Vite/Nginx），請確認有轉發：

```text
X-Forwarded-For
X-Real-IP
```

可參考：

```text
deploy/nginx/oj.conf
```

---

## Q4：同一教室多台電腦，後端看到的 IP 還是同一個

最常見原因是前端/API 都先經過同一台代理，後端只看到代理來源。

建議部署方式：

1. 對外只開 Nginx（80/443）
2. 前端走同網域 `/api/*`
3. Nginx 反向代理到後端（例如 `127.0.0.1:8000`）
4. Nginx 必須轉發 `X-Forwarded-For` / `X-Real-IP`

> 不要讓瀏覽器自己上傳 `ip` 欄位作為判定依據，該值可被偽造；IP 應以伺服器與代理層觀測值為準。

---

# 8. 開發流程建議

建議啟動順序：

### Step 1

啟動 MariaDB

↓

### Step 2

啟動 Backend：

Docker：

```bash
docker compose up --build
```

或本機：

```bash
uvicorn main:app --reload --no-proxy-headers
```

↓

### Step 3

啟動 Frontend：

```bash
cd front
npm run dev
```

↓

### Step 4

測試：

* 登入

### 登入與來源衝突

每次通過密碼驗證的登入都會記錄。三小時內發現帳號來源衝突或共用裝置／考試來源 IP 時，所有相關帳號與 Session 都會被封鎖。受保護 API 核對當前裝置 Cookie、IP 與指紋；題目只能登入後讀取，重新整理也必須通過相同檢查。

請依 [考試安全部署說明](docs/exam-security.md) 安排獨立來源 IP、預先建立帳號、配置 HTTPS 並了解共用 NAT 的限制。Cookie、指紋與主機名稱不能證明實體電腦身分。

---

# 9. 開發注意事項

* 判題環境請勿直接執行未限制權限的使用者程式。
* Docker Sandbox 必須保持 CPU / Memory / Network 限制。
* 生產環境建議：

  * 使用獨立 Docker Node
  * 限制 Container 權限
  * 啟用 Resource Quota
  * 定期清理判題 Container

---

# 10. 補充：Nginx 部署與反作弊機制

## 10.1 使用 Nginx 部署（補充步驟）

可在既有 `deploy/nginx/oj.conf` 基礎上，依下列流程部署：

1. 先建置前端靜態檔：

```bash
cd front
npm install
npm run build
```

2. 啟動後端服務（例如 `127.0.0.1:8000`）。

3. 設定 `root`、`server_name` 與考試電腦信任的 TLS 憑證／私鑰路徑，見 [HTTPS 部署步驟](docs/exam-security.md)。

4. 將 Nginx 設定檔連結到啟用目錄後重載：

```bash
sudo ln -sf /path/to/OnlineJudge/deploy/nginx/oj.conf /etc/nginx/conf.d/oj.conf
sudo nginx -t
sudo systemctl reload nginx
```

5. 驗證：

* 首頁可正常開啟（SPA 路由可直接刷新）。
* `/api/*` 會正確轉發至後端。
* 後端可收到 `X-Forwarded-For` 與 `X-Real-IP`。

若要在正式環境開放 80/443，建議保留「前端同網域 + `/api` 反向代理 + 轉發來源 IP 標頭」的拓樸，避免前後端跨網域造成額外維運與偵錯成本。

### 10.1.1 macOS（Homebrew）Nginx 部署方式

若在 macOS 上使用 Homebrew 安裝 Nginx，可參考以下補充流程：

1. 安裝與啟動：

```bash
brew install nginx
brew services start nginx
```

2. Homebrew Nginx 常見設定根目錄：

* Apple Silicon：`/opt/homebrew/etc/nginx`
* Intel：`/usr/local/etc/nginx`

3. 建議將本專案設定檔複製到 `servers` 目錄（以 Apple Silicon 為例）：

```bash
cp /path/to/OnlineJudge/deploy/nginx/oj.conf /opt/homebrew/etc/nginx/servers/oj.conf
```

4. 依本機實際路徑調整 `oj.conf` 內的 `root`（前端 `front/dist` 絕對路徑）與 `proxy_pass`（後端位址）。

5. 驗證並重載：

```bash
nginx -t
brew services restart nginx
```

6. 驗證網站與 API：

* `https://<OJ host>` 可開啟前端頁面，憑證有效且被考試電腦信任
* `/api/*` 可正常轉發到後端
* 後端可收到 `X-Forwarded-For` / `X-Real-IP`

## 10.2 考試存取與稽核

詳見 [登入規則、稽核欄位與限制](docs/exam-security.md)。新規則會中止所有相關 Session，不再只限制後登入的裝置。成功和被拒絕的提交都會保留可追查的來源資料；登入與提交寫入前的安全決策透過資料庫鎖序列化。

---

# End

### Uvicorn 代理標頭設定

啟動 Uvicorn 時必須加上 `--no-proxy-headers`（Dockerfile 已設定）。來源 IP 由應用程式依 `TRUSTED_PROXY_CIDRS` 與 Nginx 覆寫的 `X-Real-IP` 判斷；若 Uvicorn 先採信 `X-Forwarded-For`，會改寫連線來源，使應用程式的代理信任檢查失去原始依據。請只加入實際代理的精確來源 IP/CIDR；Docker 或 Docker Desktop 的代理來源未必是 loopback。

### 登入狀態恢復

前端重新整理透過 `GET /session` 恢復有效登入，接著載入題目與紀錄。它會驗證目前來源，不建立登入事件，回應帶有 `Cache-Control: no-store`。來源衝突時回應 403 並顯示重新登入／聯絡監考提示；過期或舊版未綁定 Session 則恢復為未登入。

### 同區網用戶端 IP 與 Docker Desktop

同區網電腦直接連線到 OJ 主機的內網 IP 時，主機上的 Nginx 可從 `$remote_addr` 取得該電腦的內網 IP，並覆寫 `X-Real-IP`。但 Nginx 經過 Docker 的發布埠連到後端時，後端的直接連線來源可能是 Docker 閘道，而非 `127.0.0.1`。若該來源不在 `TRUSTED_PROXY_CIDRS`，後端會安全地忽略標頭，記錄代理位址。

1. 保持後端發布埠綁定 `127.0.0.1:8000:8000`，讓內網使用者只能經過 Nginx。保持 Uvicorn 的 `--no-proxy-headers`，由應用程式處理代理信任。
2. 經 Nginx 發出一個測試請求，再從該請求的 Uvicorn access log 確認直接來源。`docker inspect` 顯示的 Gateway 只供比對；不要假設每台 Docker Desktop 都相同。
3. 在不提交的 `.env` 設定已確認的精確代理 IP，例如 `TRUSTED_PROXY_CIDRS=172.18.0.1/32,127.0.0.1/32,::1/128`。範例 IP 僅適用於觀測到該來源的部署；不要加入整段 `172.16.0.0/12` 或其他使用者網段。密鑰同樣放在 `.env`，升級時保持原值。
4. 執行 `docker compose up -d --no-deps backend` 重新建立後端，讓新的環境變數生效；單純 restart 不會更新環境變數。網路重建或 Docker 設定改變後重新確認代理来源。
5. 從另一台區網電腦直連 OJ 主機內網 IP，驗證登入紀錄等於該電腦的來源 IP；同時夾帶偽造 `X-Real-IP` 與 `X-Forwarded-For`，確認 Nginx 仍覆寫成觀測值。用 `127.0.0.1` 測試只會得到 loopback。

此信任模式假設主機及本機程序可信；不要把後端發布埠開放到外部或不可信轉送器。若用戶端經 NAT 才到達 Nginx，伺服器只能取得 NAT 後的來源，無法從 HTTP 還原 NAT 前的私有 IP。

### 登入主機名稱 `device_name`

`login_events.device_name` 保存登入時的主機名稱提示（`VARCHAR(253) NOT NULL DEFAULT ''`）。後端先以已驗證的來源 IP 查詢管理者的 `DEVICE_NAME_MAP`；未設定時，向容器使用的 DNS 解析器查詢反向 PTR 記錄，最多等待 0.5 秒。查不到、逾時或名稱格式不合法時存空字串，登入不受影響。一般瀏覽器無法直接讀取作業系統主機名稱，後端不採信用戶端自填的主機名稱標頭。

可在本機 `.env` 設定（只是一個例子，請依實際 IP 與名稱修改）：

```dotenv
DEVICE_NAME_MAP='{"192.168.137.1":"ganges-desktop"}'
```

設定後執行 `docker compose up -d --no-deps backend`。固定對照需要配合固定 IP／DHCP 保留；若要自動辨識多台電腦，請讓區網 DNS 提供各機器的 PTR 記錄，並確保後端容器能查詢該 DNS。DNS 名稱及管理者對照都是顯示資訊，不保證實體機器身分，也不參與防作弊判定。

新版本啟動時會自動新增欄位，不刪除舊資料。舊紀錄預設留空；每次登入會建立新事件並保存該次取得的名稱，舊事件與名稱不會被覆寫。查詢時可使用：

```sql
SELECT id, user_id, ip_address, device_id, device_name,
       logged_in_at, browser_fingerprint
FROM login_events
ORDER BY id DESC;
```
