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
├─ front/                  # 前端專案（React）
├─ backend/                # 後端 API 與判題邏輯
│  ├─ main.py              # FastAPI 入口
│  ├─ judge.py             # 判題核心邏輯
│  ├─ database.py          # MariaDB 連線、帳密雜湊與答題紀錄
│  └─ problems/            # 題庫目錄（每題一個資料夾）
├─ sandbox/                # 沙箱映像相關檔案
└─ docker-compose.yml      # 後端服務啟動設定
```

---

## 2. 環境配置

## 2.1 必要工具

請先安裝以下軟體：

1. **Docker**（必須，可用於判題沙箱）
2. **Docker Compose**（或 `docker compose`）
3. **Node.js 18+**（前端）
4. **Python 3.10+**（本機直接跑後端時需要）

## 2.2 後端環境變數

`backend/judge.py` 與 `backend/database.py` 使用以下環境變數：

- `JUDGE_IMAGE`：判題沙箱映像名稱，預設 `onlineoj-sandbox:latest`
- `HOST_BACKEND_DIR`：主機上 backend 的絕對路徑，供 Docker in Docker 掛載工作目錄
- `MARIADB_HOST`：MariaDB host，Docker Compose 內預設為 `mariadb`
- `MARIADB_PORT`：MariaDB port，預設為 `3306`
- `MARIADB_USER` / `MARIADB_PASSWORD` / `MARIADB_DATABASE`：資料庫帳號、密碼與資料庫名稱

> 注意：若未設定 `HOST_BACKEND_DIR`，`docker-compose.yml` 會使用 `${PWD}/backend`。如果你的 shell 沒有提供 `PWD`，請改用自己的實際絕對路徑，否則提交時無法正確掛載暫存程式碼。

---

## 3. 啟動方式

## 3.1 啟動後端（建議）

在專案根目錄執行：

```bash
docker compose up --build backend
```

啟動後 API 預設在：

- `http://localhost:8000/`

可先測試：

```bash
curl http://localhost:8000/
```

預期回傳：

```json
{"message":"Simple OJ Running"}
```

## 3.2 啟動前端

另開一個終端機：

```bash
cd front
npm install
npm run dev
```

前端預設網址（Vite）：

- `http://localhost:5173/`

---

## 4. 如何「入題庫」（新增題目）

題庫根目錄：

- `backend/problems/`

每一題使用一個資料夾，資料夾名稱就是 `problem_id`，例如 `1003`：

```text
backend/problems/1003/
├─ input1.txt
├─ output1.txt
├─ input2.txt
├─ output2.txt
└─ ...
```

規則：

1. 測資檔名必須是 `inputN.txt` / `outputN.txt` 成對。
2. `N` 建議從 `1` 開始連續編號。
3. 若缺少任一對應 `output` 檔，提交會回傳錯誤。
4. 系統會依檔名排序逐一測試，任一組錯誤即停止並回傳該測資編號。

最小範例：

```text
backend/problems/1003/input1.txt
backend/problems/1003/output1.txt
```

---

## 5. 題目敘述設定

目前題目標題與敘述定義在：

- `backend/main.py` 的 `PROBLEM_INFO` 字典

範例：

```python
PROBLEM_INFO = {
    "1001": {
        "title": "infix to postfix 四則運算",
        "description": "輸入中敘式，輸出四則運算後的答案",
    },
    "1002": {
        "title": "A + B Problem",
        "description": "讀入兩個整數 a 與 b，輸出 a + b。",
    }
}
```

若你新增了 `backend/problems/1003`，也建議同步在 `PROBLEM_INFO` 新增：

```python
"1003": {
    "title": "題目名稱",
    "description": "題目敘述內容",
}
```

若未設定，系統會顯示預設值：

- title: `Problem <problem_id>`
- description: `尚無題目敘述。`

---

## 6. 帳號與答題紀錄

後端提供以下帳號 API：

- `POST /register`：欄位 `username`, `password`，建立帳號。密碼會依需求以 `password + username` 作為輸入進行 SHA-256 雜湊後存入 MariaDB。
- `POST /login`：欄位 `username`, `password`，驗證帳號密碼。
- `POST /submissions`：欄位 `username`, `password`，取得該帳號最近 100 筆答題紀錄。

答題紀錄會在登入使用者提交後寫入 MariaDB 的 `submissions` 資料表，包含題號、語言、判題狀態、完整判題 JSON 與提交時間。

---

## 7. 判題流程說明

提交 API：

- `POST /submit`
- 欄位：`language`, `code`, `problem_id`, `username`, `password`

目前支援語言：

- `c`
- `cpp`

判題結果可能包含：

- `AC`：全部通過
- `WA`：答案錯誤
- `CE`：編譯錯誤
- `RE`：執行期錯誤
- `TLE`：超時
- `MLE`：記憶體超限（容器被系統終止）
- `ERROR`：題庫缺漏或參數問題

---

## 8. API 快速測試

## 8.1 取得題目列表

```bash
curl http://localhost:8000/problems
```

## 8.2 提交 C++ 程式

```bash
curl -X POST http://localhost:8000/submit \
  -F "language=cpp" \
  -F "problem_id=1001" \
  -F "username=demo" \
  -F "password=demo123" \
  -F 'code=#include <bits/stdc++.h>\nusing namespace std;\nint main(){cout<<"hello";}'
```

---

## 9. 常見問題（FAQ）

1. **提交後出現 `No testcases`**
   - 檢查 `backend/problems/<problem_id>/` 下是否有 `input*.txt`。

2. **提交一直 `ERROR` 或找不到暫存檔**
   - 檢查 `HOST_BACKEND_DIR` 是否為你的真實絕對路徑。

3. **前端讀不到 API**
   - 確認後端是否在 `8000` port 啟動，並檢查前端 API base URL 設定。

---

## 10. 建議維運做法

- 新增題目時，先放至少 1 組 sample（`input1/output1`）。
- 測資請避免尾端多餘空白，以免比對誤差。
- 若要擴充語言（如 Python），可在 `backend/judge.py` 新增對應 `judge_xxx` 流程。
