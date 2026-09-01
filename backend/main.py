from pathlib import Path

import ipaddress
import logging
import os
import re
import secrets
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from judge import judge_submission
from pymysql.err import IntegrityError

from database import (
    authenticate_user,
    create_user,
    create_session,
    find_recent_other_user_on_device,
    get_session,
    init_db,
    is_submission_blocked,
    list_login_alerts_for_user,
    list_submissions,
    record_submission_attempt,
    record_login,
    save_submission,
)

app = FastAPI()
logger = logging.getLogger(__name__)
SESSION_COOKIE = "oj_session"
DEVICE_COOKIE = "oj_device"


@app.on_event("startup")
def startup():
    init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8080").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def build_problem_item(problem_id: str, problem_dir: Path):
    title_file = problem_dir / "title.txt"
    description_file = problem_dir / "description.txt"

    title = title_file.read_text(encoding="utf-8").strip() if title_file.exists() else f"Problem {problem_id}"
    description = description_file.read_text(encoding="utf-8").strip() if description_file.exists() else "尚無題目敘述。"

    sample_input_file = problem_dir / "input1.txt"
    sample_output_file = problem_dir / "output1.txt"
    sample_input = sample_input_file.read_text(encoding="utf-8").strip() if sample_input_file.exists() else ""
    sample_output = sample_output_file.read_text(encoding="utf-8").strip() if sample_output_file.exists() else ""

    return {
        "id": problem_id,
        "title": title,
        "description": description,
        "sample_input": sample_input,
        "sample_output": sample_output,
    }


def is_valid_problem_id(problem_id: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", problem_id or ""):
        return False
    problems_root = Path(__file__).resolve().parent / "problems"
    if not problems_root.exists():
        return False
    return any(problem_dir.name == problem_id for problem_dir in problems_root.iterdir() if problem_dir.is_dir())


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
def register(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if len(username) < 3 or len(username) > 64:
        raise HTTPException(status_code=400, detail="帳號需為 3 到 64 個字元")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="密碼至少需要 6 個字元")

    try:
        user = create_user(username, password)
        device_id = _device_id(request, response)
        _set_session(response, user["id"], device_id)
        return {"user": user}
    except IntegrityError:
        raise HTTPException(status_code=409, detail="帳號已存在")


def _parse_valid_ip(value: str) -> str | None:
    candidate = (value or "").strip()
    if not candidate:
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _forwarded_ip_candidates(request: Request) -> list[str]:
    candidates: list[str] = []
    x_forwarded_for = request.headers.get("x-forwarded-for", "")
    if x_forwarded_for:
        for item in x_forwarded_for.split(","):
            ip = _parse_valid_ip(item)
            if ip:
                candidates.append(ip)

    x_real_ip = _parse_valid_ip(request.headers.get("x-real-ip", ""))
    if x_real_ip:
        candidates.append(x_real_ip)
    return candidates


def client_ip(request: Request) -> str:
    """Prefer private LAN client IPs from trusted internal proxies."""
    direct_ip = _parse_valid_ip(request.client.host if request.client else "")
    forwarded_candidates = _forwarded_ip_candidates(request)
    if direct_ip:
        direct_ip_obj = ipaddress.ip_address(direct_ip)
        if direct_ip_obj.is_private or direct_ip_obj.is_loopback:
            for forwarded_ip in forwarded_candidates:
                forwarded_obj = ipaddress.ip_address(forwarded_ip)
                if (
                    forwarded_obj.is_private
                    or forwarded_obj.is_loopback
                    or forwarded_obj.is_link_local
                ):
                    return forwarded_ip
            if forwarded_candidates:
                return forwarded_candidates[0]
        return direct_ip
    if forwarded_candidates:
        return forwarded_candidates[0]
    return "unknown"


def _device_id(request: Request, response: Response) -> str:
    value = request.cookies.get(DEVICE_COOKIE)
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError):
        value = str(UUID(bytes=secrets.token_bytes(16)))
        response.set_cookie(
            DEVICE_COOKIE, value, max_age=60 * 60 * 24 * 365,
            httponly=True, secure=False, samesite="lax",
        )
        return value


def _set_session(response: Response, user_id: int, device_id: str):
    token = create_session(user_id, device_id)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=60 * 60 * 12,
        httponly=True, secure=False, samesite="lax",
    )


def authenticated_session(request: Request):
    session = get_session(request.cookies.get(SESSION_COOKIE))
    if not session:
        raise HTTPException(status_code=401, detail="請先登入")
    return session


@app.post("/login")
def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate_user(username.strip(), password)
    if user is None:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    device_id = _device_id(request, response)
    ip = client_ip(request)
    other_user = find_recent_other_user_on_device(user["id"], device_id)
    if other_user:
        logger.warning(
            "Multiple-account login blocked username=%s user_id=%s ip=%s "
            "browser_device_id=%s previous_username=%s previous_user_id=%s",
            user["username"],
            user["id"],
            ip,
            device_id,
            other_user["username"],
            other_user["id"],
        )
        raise HTTPException(status_code=403, detail="此裝置三小時內已登入其他帳號，暫時無法登入")
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
    _set_session(response, user["id"], device_id)
    return {"user": user, "login_alert": new_alert}


@app.post("/login-alerts")
def login_alerts(request: Request):
    session = authenticated_session(request)
    return list_login_alerts_for_user(session["user_id"])


@app.post("/submit")
def submit(
    request: Request,
    language: str = Form(...),
    code: str = Form(...),
    problem_id: str = Form(...),
):
    session = authenticated_session(request)
    problem_id = problem_id.strip()
    if not is_valid_problem_id(problem_id):
        raise HTTPException(status_code=400, detail="無效的題號")
    if is_submission_blocked(session["user_id"], session["device_id"]):
        raise HTTPException(
            status_code=403,
            detail="偵測到三小時內有異地登入，暫時無法提交答案",
        )
    retry_after = record_submission_attempt(session["user_id"], problem_id)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail=f"提交過於頻繁，請 {retry_after} 秒後再試",
            headers={"Retry-After": str(retry_after)},
        )

    result = judge_submission(language, code, problem_id)
    submission_id = save_submission(
        session["user_id"],
        session["username"],
        problem_id,
        language,
        result,
        code,
    )
    return {**result, "submission_id": submission_id}


@app.post("/submissions")
def submissions(request: Request):
    session = authenticated_session(request)
    return list_submissions(session["user_id"])
