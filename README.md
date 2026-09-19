# OnlineJudge 使用說明書

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
| `TRUSTED_PROXY_CIDRS` | 可提供 `X-Real-IP` 的可信代理 CIDR（逗號分隔） | `127.0.0.0/8,::1/128` |

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

可使用 `openssl rand -hex 32` 產生 `DEVICE_SECRET`。請勿提交此密鑰，且所有後端實例必須使用相同值。若目前只使用範例中的 HTTP Nginx，需明確設定 `COOKIE_SECURE=false`；啟用 TLS 後應改回 `true`。

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
Backend API:
http://localhost:8000
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
uvicorn main:app --reload --host 0.0.0.0 --port 8000
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
uvicorn main:app --reload
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

### 異地登入偵測

登入時，系統會記錄連線 IP 與瀏覽器保存的裝置識別碼。同一個校園、公司或家庭網路的多台電腦常會經由 NAT 共用同一個對外 IP，因此異地登入以不同裝置識別碼判定，而非僅依 IP。IP 仍會保留在警告中供管理者比對。

同一帳號在三小時內由不同裝置識別碼登入時，後端會記錄並輸出警告；只有後登入的裝置會立即看到警告，並在三小時內被拒絕提交答案。先登入的裝置不會因後續有人嘗試登入而被中斷或阻擋提交。

異地登入提示會在後登入裝置的重新登入或 F5 後持續顯示至三小時窗口結束；先登入裝置不會顯示該提示。為避免多人共用帳號規避偵測，同一個瀏覽器裝置識別碼在三小時內也只能登入一個帳號；登入第二個帳號會被後端拒絕並記錄在日誌中。

瀏覽器基於安全與隱私限制，網頁無法讀取使用者網卡的真實 MAC 位址。因此後端會產生隨機 UUID、以 HMAC 簽章後保存於 HttpOnly Cookie；它不是實體硬體身分，也不能防止使用者清除 Cookie。每次偵測到異地登入時，後端日誌會輸出帳號、兩端 IP、裝置識別碼與輔助用的瀏覽器指紋，方便管理者追查。

只有直接連線來源符合 `TRUSTED_PROXY_CIDRS` 時，後端才採用代理覆寫的 `X-Real-IP`；其他連線所帶的來源 IP 標頭一律忽略。範例 Nginx 會以 `$remote_addr` 覆寫該標頭，避免沿用客戶端自行提供的值。
* 題目列表
* 提交程式
* 判題結果
* 資料庫紀錄

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

3. 將 `deploy/nginx/oj.conf` 內的 `root` 改為你的 `front/dist` 絕對路徑。

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

* `http://localhost:8080` 可開啟前端頁面
* `/api/*` 可正常轉發到後端
* 後端可收到 `X-Forwarded-For` / `X-Real-IP`

## 10.2 反作弊機制（補充說明）

目前系統的防作弊核心是「帳號 + 瀏覽器裝置識別碼 + 時間窗口」聯合判定，重點如下：

1. 不以前端回傳的任意欄位作為可信依據，來源 IP 以伺服器/代理層觀測值為準。
2. 三小時內同帳號若出現不同裝置識別碼登入，會觸發異地登入警告並限制後登入端提交。
3. 三小時內同一裝置識別碼僅允許登入一個帳號，降低共用裝置輪替帳號的規避行為。
4. 重新整理頁面不會改變同一瀏覽器的裝置識別碼，避免誤判。
5. 裝置 Cookie 由後端以部署專用密鑰簽章；無效或舊版未簽章 Cookie 會被替換，而不會由伺服器代為簽章。
6. 後端日誌保留帳號、IP 與裝置識別碼，提供管理者事後稽核依據。

管理建議：

* 於校內或公司內網部署時，請將代理實際來源位址（建議精確 `/32` 或 `/128`）加入 `TRUSTED_PROXY_CIDRS`，並確保代理覆寫 `X-Real-IP`。不要把整個私人網段視為可信代理，否則能直接連到後端的內網用戶可偽造來源 IP。
* 對於共用 NAT 環境（教室、宿舍、辦公室），請以「裝置識別碼差異」為主要告警依據，IP 用於輔助比對。
* 瀏覽器指紋與所有前端標頭都可由惡意客戶端修改，只能作為風險訊號，不能視為可信的硬體身分。若考試需要強身分綁定，應另行採用受管理裝置憑證或 WebAuthn 等機制。

---

# End
