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

目前 `docker-compose.yml` 內 `backend` 服務預設：

```env
HOST_BACKEND_DIR=${HOST_BACKEND_DIR:-${PWD}/backend}

MARIADB_HOST=host.docker.internal
MARIADB_PORT=3306
MARIADB_USER=onlinejudge
MARIADB_PASSWORD=onlinejudge
MARIADB_DATABASE=onlinejudge
```

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

# End
