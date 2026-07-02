# OnlineJudge 使用說明書

本專案是一個簡易版 Online Judge（OJ）系統，採用：

- **前端**：React + Vite
- **後端**：FastAPI
- **判題沙箱**：Docker 容器（限制 CPU / 記憶體 / 網路）
- **資料庫**：MariaDB（帳號與答題紀錄）

---

## 1. 專案結構

```text
OnlineJudge/
├─ front/                  # 前端專案（React + Vite）
├─ backend/                # 後端 API 與判題邏輯
│  ├─ main.py              # FastAPI 入口
│  ├─ judge.py             # 判題核心邏輯
│  ├─ database.py          # MariaDB 連線與資料操作
│  ├─ requirements.txt     # 後端套件
│  └─ problems/            # 題庫目錄（每題一個資料夾）
├─ sandbox/                # 沙箱映像相關檔案
└─ docker-compose.yml      # 後端容器啟動設定
```

---

## 2. 先決條件

請先安裝以下工具：

1. **Docker**
2. **Docker Compose**（或 `docker compose`）
3. **Node.js 18+**（前端）
4. **Python 3.10+**（本機直接執行後端時）

---

## 3. 環境變數說明（後端）

後端主要使用以下變數：

- `JUDGE_IMAGE`：判題沙箱映像名稱（預設：`onlineoj-sandbox:latest`）
- `HOST_BACKEND_DIR`：主機上 `backend` 的**絕對路徑**（提供沙箱掛載）
- `MARIADB_HOST`
- `MARIADB_PORT`（預設 `3306`）
- `MARIADB_USER`
- `MARIADB_PASSWORD`
- `MARIADB_DATABASE`

目前 `docker-compose.yml` 內 `backend` 服務預設為：

- `HOST_BACKEND_DIR=${HOST_BACKEND_DIR:-${PWD}/backend}`
- `MARIADB_HOST=host.docker.internal`
- `MARIADB_PORT=3306`
- `MARIADB_USER=onlinejudge`
- `MARIADB_PASSWORD=onlinejudge`
- `MARIADB_DATABASE=onlinejudge`

> 若你的環境沒有 `PWD`，請手動設定 `HOST_BACKEND_DIR` 為實際絕對路徑，避免判題掛載失敗。

---

## 4. 啟動方式

### 4.1 使用 Docker Compose（後端）

在專案根目錄執行：

```bash
docker compose up -d --build
```

後端服務啟動後預設對外埠為：

- `http://localhost:8000`

> 目前 `docker-compose.yml` 僅啟動 `backend`，不包含前端與 MariaDB 容器。  
> `MARIADB_HOST` 預設是 `host.docker.internal`，代表你需要在主機端先有可連線的 MariaDB。

---

### 4.2 前端啟動（本機開發）

進入前端目錄後執行：

```bash
cd front
npm install
npm run dev
```

其他可用指令（來自 `front/package.json`）：

```bash
npm run build
npm run preview
```

---

### 4.3 後端本機啟動（不透過 Docker）

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

`backend/requirements.txt` 目前包含：

- fastapi
- uvicorn
- python-multipart
- pymysql

---

## 5. 資料庫設定建議

請先確認 MariaDB 已建立：

- 資料庫：`onlinejudge`
- 使用者：`onlinejudge`
- 密碼：`onlinejudge`
- 連線位址：`host.docker.internal:3306`（依你的環境可調整）

若你使用 Linux，`host.docker.internal` 可能無法直接使用，請改為實際主機 IP 或將 DB 改成同一個 compose 內服務名稱。

---

## 6. 常見問題

### Q1：提交後判題找不到掛載路徑
- 檢查 `HOST_BACKEND_DIR` 是否為主機上的 `backend` 絕對路徑。
- 確認 Docker 有掛載 `/var/run/docker.sock`（compose 已設定）。

### Q2：後端啟動但資料庫連不上
- 檢查 MariaDB 是否真的在 `MARIADB_HOST:MARIADB_PORT` 上可連線。
- 確認帳號密碼與資料庫名稱一致。
- Linux 環境若使用 `host.docker.internal` 失敗，請改用主機 IP。

### Q3：前端可以開啟但 API 失敗
- 確認後端有在 `:8000` 運行。
- 檢查前端 API base URL 是否指向正確主機與埠號。

---

## 7. 開發流程建議

1. 先啟動 MariaDB
2. 啟動後端（Docker 或本機）
3. 啟動前端（`front/`）
4. 透過前端提交程式碼，觀察後端判題與資料庫寫入結果
