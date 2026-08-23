from pathlib import Path

import logging
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from judge import judge_submission
from pymysql.err import IntegrityError

from database import (
    authenticate_user,
    create_user,
    init_db,
    is_submission_blocked,
    list_login_alerts_for_user,
    list_submissions,
    record_login,
    save_submission,
)

app = FastAPI()
logger = logging.getLogger(__name__)


@app.on_event("startup")
def startup():
    init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


def build_problem_item(problem_id: str, problem_dir: Path):
    info = PROBLEM_INFO.get(
        problem_id,
        {"title": f"Problem {problem_id}", "description": "尚無題目敘述。"},
    )

    sample_input_file = problem_dir / "input1.txt"
    sample_output_file = problem_dir / "output1.txt"
    sample_input = sample_input_file.read_text(encoding="utf-8").strip() if sample_input_file.exists() else ""
    sample_output = sample_output_file.read_text(encoding="utf-8").strip() if sample_output_file.exists() else ""

    return {
        "id": problem_id,
        "title": info["title"],
        "description": info["description"],
        "sample_input": sample_input,
        "sample_output": sample_output,
    }


@app.get("/")
def root():
    return {"message": "Simple OJ Running"}


@app.get("/problems")
def list_problems():
    problems_root = Path(__file__).resolve().parent / "problems"
    if not problems_root.exists():
        return []

    problem_items = []
    for problem_dir in sorted(path for path in problems_root.iterdir() if path.is_dir()):
        problem_items.append(build_problem_item(problem_dir.name, problem_dir))

    return problem_items



@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if len(username) < 3 or len(username) > 64:
        raise HTTPException(status_code=400, detail="帳號需為 3 到 64 個字元")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="密碼至少需要 6 個字元")

    try:
        return {"user": create_user(username, password)}
    except IntegrityError:
        raise HTTPException(status_code=409, detail="帳號已存在")


def client_ip(request: Request) -> str:
    """Use the connection IP; configure a trusted proxy to preserve client IPs."""
    return request.client.host if request.client else "unknown"


def validate_login_device(device_id: str) -> str:
    try:
        return str(UUID(device_id))
    except (TypeError, ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="無效的裝置識別碼")


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    device_id: str = Form(...),
):
    user = authenticate_user(username.strip(), password)
    if user is None:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    device_id = validate_login_device(device_id)
    ip = client_ip(request)
    _, new_alert = record_login(user["id"], ip, device_id)
    if new_alert:
        logger.warning(
            "Cross-device login warning username=%s user_id=%s "
            "first_ip=%s first_browser_device_id=%s "
            "attempted_ip=%s attempted_browser_device_id=%s",
            user["username"],
            user["id"],
            new_alert["first_ip_address"],
            new_alert["first_device_id"],
            new_alert["second_ip_address"],
            new_alert["second_device_id"],
        )
    return {"user": user, "login_alert": new_alert}


@app.post("/login-alerts")
def login_alerts(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username.strip(), password)
    if user is None:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    return list_login_alerts_for_user(user["id"])


@app.post("/submit")
def submit(
    language: str = Form(...),
    code: str = Form(...),
    problem_id: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    device_id: str = Form(...),
):
    user = authenticate_user(username.strip(), password)
    if user is None:
        raise HTTPException(status_code=401, detail="請先登入後再提交")
    if is_submission_blocked(user["id"], validate_login_device(device_id)):
        raise HTTPException(
            status_code=403,
            detail="偵測到三小時內有異地登入，後登入的裝置暫時無法提交答案",
        )

    result = judge_submission(language, code, problem_id)
    submission_id = save_submission(
        user["id"],
        user["username"],
        problem_id,
        language,
        result
    )
    return {**result, "submission_id": submission_id}


@app.post("/submissions")
def submissions(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username.strip(), password)
    if user is None:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    return list_submissions(user["id"])
