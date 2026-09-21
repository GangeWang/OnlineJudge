from pathlib import Path
from contextlib import asynccontextmanager
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from starlette.concurrency import run_in_threadpool
from judge import judge_submission
from device_names import configured_device_names, resolve_device_name
from pymysql.err import IntegrityError

from database import (
    authenticate_user, create_user, init_db, list_submissions,
    record_submission_attempt, save_submission,
)
from session_security import (
    audit_submission, check_session, finish_audit, issue_session,
    registration_enabled, security_transaction,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed at startup instead of silently signing cookies with a public key.
    _device_secret()
    if not _cookie_secure() and not _allow_insecure_http():
        raise RuntimeError("COOKIE_SECURE=false requires ALLOW_INSECURE_HTTP=true for local development")
    configured_device_names()
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
logger = logging.getLogger(__name__)
SESSION_COOKIE = "oj_session"
DEVICE_COOKIE = "oj_device"

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "https://localhost").split(","),
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
def list_problems(request: Request):
    authenticated_session(request)
    problems_root = Path(__file__).resolve().parent / "problems"
    if not problems_root.exists():
        return []

    problem_items = []
    for problem_dir in sorted(path for path in problems_root.iterdir() if path.is_dir()):
        problem_items.append(build_problem_item(problem_dir.name, problem_dir))

    return problem_items


MIN_DEVICE_SECRET_BYTES = 32

def _device_secret() -> bytes:
    """Return the deployment secret used to authenticate device cookies."""
    value = os.getenv("DEVICE_SECRET", "").encode("utf-8")
    if len(value) < MIN_DEVICE_SECRET_BYTES:
        raise RuntimeError(
            f"DEVICE_SECRET must be set to at least {MIN_DEVICE_SECRET_BYTES} bytes"
        )
    return value

def _cookie_secure() -> bool:
    return os.getenv("COOKIE_SECURE", "true").lower() not in {"0", "false", "no"}

def _sign_device_id(raw_uuid: str) -> str:
    sig = hmac.new(_device_secret(), raw_uuid.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{raw_uuid}.{sig}"

def _verify_device_id(signed_value: str | None) -> str | None:
    if not signed_value or "." not in signed_value:
        return None
    parts = signed_value.split(".", 1)
    if len(parts) != 2:
        return None
    raw_uuid, sig = parts
    if not re.fullmatch(r"[0-9a-f]{64}", sig):
        return None
    try:
        UUID(raw_uuid)
    except (TypeError, ValueError, AttributeError):
        return None
    expected = hmac.new(_device_secret(), raw_uuid.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return raw_uuid
    return None

def _browser_fingerprint(request: Request) -> str:
    """Client-controlled risk signal; never proof of physical machine identity."""
    ua = request.headers.get("user-agent", "")
    lang = request.headers.get("accept-language", "")
    sec_ch_ua = request.headers.get("sec-ch-ua", "")
    sec_platform = request.headers.get("sec-ch-ua-platform", "")
    encoding = request.headers.get("accept-encoding", "")
    client_fp = request.headers.get("x-client-fingerprint", "")
    raw = f"{ua}|{lang}|{sec_ch_ua}|{sec_platform}|{encoding}|{client_fp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@app.post("/register")
def register(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    if not registration_enabled():
        raise HTTPException(status_code=403, detail="目前未開放註冊，請使用預先建立的帳號")
    username = username.strip()
    if len(username) < 3 or len(username) > 64:
        raise HTTPException(status_code=400, detail="帳號需為 3 到 64 個字元")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="密碼至少需要 6 個字元")

    try:
        user = create_user(username, password)
        return _login_user(request, response, user)
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

def client_ip(request: Request) -> str:
    """
    Extract client IP securely.
    Only trust forwarded headers if the direct connection is in TRUSTED_PROXY_CIDRS.
    When trusted, use X-Real-IP set by Nginx ($remote_addr).
    Does not trust spoofable client-supplied X-Forwarded-For headers.
    """
    direct_ip = _parse_valid_ip(request.client.host if request.client else "")
    if direct_ip:
        direct_ip_obj = ipaddress.ip_address(direct_ip)
        if _trusted_proxy(direct_ip_obj):
            x_real_ip = _parse_valid_ip(request.headers.get("x-real-ip", ""))
            if x_real_ip:
                return x_real_ip
        return direct_ip
    return "unknown"


def _trusted_proxy(address):
    for value in os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128").split(","):
        if value.strip():
            try:
                if address in ipaddress.ip_network(value.strip(), strict=False):
                    return True
            except ValueError:
                logger.error("Ignoring invalid TRUSTED_PROXY_CIDRS entry: %s", value)
    return False

def _allow_insecure_http():
    return os.getenv("ALLOW_INSECURE_HTTP", "false").lower() in {"true", "1", "yes"}


@app.middleware("http")
async def require_https(request: Request, call_next):
    direct_ip = _parse_valid_ip(request.client.host if request.client else "")
    proxied_tls = (direct_ip and _trusted_proxy(ipaddress.ip_address(direct_ip))
                   and request.headers.get("x-forwarded-proto") == "https")
    if not _allow_insecure_http() and request.url.scheme != "https" and not proxied_tls:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "HTTPS required"}, status_code=400, headers={"Cache-Control": "no-store"})
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def audit_invalid_submission(request: Request, exc: RequestValidationError):
    if request.url.path == "/submit" and request.method == "POST":
        audit_id = await run_in_threadpool(
            audit_submission, request_context(request), "", request.cookies.get(SESSION_COOKIE),
        )
        await run_in_threadpool(finish_audit, audit_id, "denied_422")
    return await request_validation_exception_handler(request, exc)


@app.get("/auth-config")
def auth_config():
    return {"registration_enabled": registration_enabled()}


def _device_id(request: Request, response: Response) -> str:
    cookie_val = request.cookies.get(DEVICE_COOKIE)
    valid_uuid = _verify_device_id(cookie_val)
    if valid_uuid:
        return valid_uuid
    new_uuid = str(UUID(bytes=secrets.token_bytes(16)))
    response.set_cookie(
        DEVICE_COOKIE, _sign_device_id(new_uuid), max_age=60 * 60 * 24 * 365,
        httponly=True, secure=_cookie_secure(), samesite="lax",
    )
    return new_uuid


def request_context(request):
    return {
        "device_id": _verify_device_id(request.cookies.get(DEVICE_COOKIE)) or "",
        "ip_address": client_ip(request),
        "browser_fingerprint": _browser_fingerprint(request),
    }

def _deny_session(error):
    raise HTTPException(status_code=error, detail=("請先登入" if error == 401 else "偵測到登入來源衝突，所有相關登入已停用，請聯絡監考人員"))

def authenticated_session(request: Request):
    with security_transaction() as connection:
        session, error = check_session(connection, request.cookies.get(SESSION_COOKIE), request_context(request))
    if error:
        _deny_session(error)
    return session

def _login_user(request, response, user):
    context = request_context(request)
    context["device_id"] = _device_id(request, response)
    token = issue_session(user["id"], context, resolve_device_name(context["ip_address"]))
    if not token:
        _deny_session(403)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=60 * 60 * 12,
        httponly=True, secure=_cookie_secure(), samesite="lax",
    )
    return {"user": user, "login_alert": None}


@app.post("/login")
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username.strip(), password)
    if user is None:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    return _login_user(request, response, user)


@app.get("/session")
def current_session(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    with security_transaction() as connection:
        session, error = check_session(connection, request.cookies.get(SESSION_COOKIE), request_context(request))
    if error == 401:
        return {"user": None, "login_alerts": []}
    if error:
        _deny_session(error)
    return {"user": {"id": session["user_id"], "username": session["username"]}, "login_alerts": []}


@app.post("/login-alerts")
def login_alerts(request: Request):
    authenticated_session(request)
    return []


@app.post("/submit")
def submit(
    request: Request,
    language: str = Form(...),
    code: str = Form(...),
    problem_id: str = Form(...),
):
    context = request_context(request)
    token = request.cookies.get(SESSION_COOKIE)
    audit_id = audit_submission(context, problem_id, token)
    session = None
    submission_id = None
    outcome = "error"
    try:
        with security_transaction() as connection:
            session, error = check_session(connection, token, context)
        if error:
            _deny_session(error)
        problem_id = problem_id.strip()
        if not is_valid_problem_id(problem_id):
            raise HTTPException(status_code=400, detail="無效的題號")
        retry_after = record_submission_attempt(session["user_id"], problem_id)
        if retry_after:
            raise HTTPException(status_code=429, detail=f"提交過於頻繁，請 {retry_after} 秒後再試", headers={"Retry-After": str(retry_after)})
        result = judge_submission(language, code, problem_id)
        # Recheck after judging so a concurrent conflict cannot persist an accepted
        # submission. The check and persistence share the policy transaction.
        with security_transaction() as connection:
            session, error = check_session(connection, token, context)
            if not error:
                submission_id = save_submission(
                    connection, session["user_id"], session["username"], problem_id,
                    language, result, code, {**context, "session_hash": session["token_hash"]},
                )
        if error:
            _deny_session(error)
        outcome = "accepted"
        return {**result, "submission_id": submission_id}
    except HTTPException as exc:
        outcome = f"denied_{exc.status_code}"
        raise
    finally:
        finish_audit(audit_id, outcome, session["user_id"] if session else None, submission_id)


@app.post("/submissions")
def submissions(request: Request):
    session = authenticated_session(request)
    return list_submissions(session["user_id"])
