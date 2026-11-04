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
from judge import judge_submission
from device_names import configured_device_names, resolve_device_name
from pymysql.err import IntegrityError

from database import (
    authenticate_user,
    create_user,
    create_session,
    db_config,
    NO_USER_ID,
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed at startup instead of silently signing cookies with a public key.
    _device_secret()
    db_config()
    configured_device_names()
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
logger = logging.getLogger(__name__)
SESSION_COOKIE = "oj_session"
DEVICE_COOKIE = "oj_device"

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:80").split(","),
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


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return default
    return value not in {"0", "false", "no", "off"}


def _lan_exam_mode() -> bool:
    """Every exam seat has its own LAN IP, so the client IP becomes part of device identity.

    Off by default because NAT networks (campus, home, office) share one IP between machines.
    """
    return _env_flag("LAN_EXAM_MODE", False)


def _registration_open() -> bool:
    return _env_flag("ALLOW_REGISTRATION", True)


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
    """Deterministic SHA-256 fingerprint generated from browser headers and client hardware fingerprint."""
    ua = request.headers.get("user-agent", "")
    lang = request.headers.get("accept-language", "")
    sec_ch_ua = request.headers.get("sec-ch-ua", "")
    sec_platform = request.headers.get("sec-ch-ua-platform", "")
    encoding = request.headers.get("accept-encoding", "")
    client_fp = request.headers.get("x-client-fingerprint", "")
    raw = f"{ua}|{lang}|{sec_ch_ua}|{sec_platform}|{encoding}|{client_fp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


MULTI_ACCOUNT_DETAIL = "此裝置三小時內已登入其他帳號，暫時無法登入"


def _reject_if_device_has_other_account(
    user_id: int, username: str, device_id: str, ip: str, fingerprint: str, lan_mode: bool,
):
    other_user = find_recent_other_user_on_device(user_id, device_id, ip, fingerprint, lan_mode=lan_mode)
    if other_user:
        logger.warning(
            "Multiple-account login blocked username=%s user_id=%s ip=%s "
            "browser_device_id=%s browser_fingerprint=%s previous_username=%s previous_user_id=%s",
            username,
            user_id,
            ip,
            device_id,
            fingerprint,
            other_user["username"],
            other_user["id"],
        )
        raise HTTPException(status_code=403, detail=MULTI_ACCOUNT_DETAIL)


def _record_login_and_start_session(
    response: Response, user: dict, device_id: str, ip: str, fingerprint: str, lan_mode: bool,
):
    device_name = resolve_device_name(ip)
    _, new_alert = record_login(
        user["id"], ip, device_id, fingerprint, device_name=device_name, lan_mode=lan_mode,
    )
    if new_alert:
        logger.warning(
            "Cross-device login warning username=%s user_id=%s "
            "first_ip=%s first_browser_device_id=%s first_browser_fp=%s "
            "attempted_ip=%s attempted_browser_device_id=%s attempted_browser_fp=%s",
            user["username"],
            user["id"],
            new_alert["first_ip_address"],
            new_alert["first_device_id"],
            new_alert.get("first_browser_fp", ""),
            new_alert["second_ip_address"],
            new_alert["second_device_id"],
            new_alert.get("second_browser_fp", ""),
        )
    _set_session(response, user["id"], device_id, fingerprint, ip)
    return new_alert


@app.post("/register")
def register(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    if not _registration_open():
        raise HTTPException(status_code=403, detail="目前不開放自行註冊，請使用管理者提供的帳號")
    username = username.strip()
    if len(username) < 3 or len(username) > 64:
        raise HTTPException(status_code=400, detail="帳號需為 3 到 64 個字元")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="密碼至少需要 6 個字元")

    # Registration signs the new account in, so it obeys the same rules as /login:
    # check the device before creating the account, then record the login event.
    device_id = _device_id(request, response)
    ip = client_ip(request)
    fingerprint = _browser_fingerprint(request)
    lan_mode = _lan_exam_mode()
    _reject_if_device_has_other_account(NO_USER_ID, username, device_id, ip, fingerprint, lan_mode)
    try:
        user = create_user(username, password)
    except IntegrityError:
        raise HTTPException(status_code=409, detail="帳號已存在")
    _record_login_and_start_session(response, user, device_id, ip, fingerprint, lan_mode)
    return {"user": user}


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
        configured = os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128")
        trusted_proxies = []
        for value in configured.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                trusted_proxies.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                logger.error("Ignoring invalid TRUSTED_PROXY_CIDRS entry: %s", value)
        if any(direct_ip_obj in network for network in trusted_proxies):
            x_real_ip = _parse_valid_ip(request.headers.get("x-real-ip", ""))
            if x_real_ip:
                return x_real_ip
        return direct_ip
    return "unknown"


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


def _set_session(response: Response, user_id: int, device_id: str, browser_fingerprint: str = "", ip: str = ""):
    token = create_session(user_id, device_id, browser_fingerprint, ip)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=60 * 60 * 12,
        httponly=True, secure=_cookie_secure(), samesite="lax",
    )


def _bound_session(request: Request):
    """Return the session only when presented with the device cookie it was issued to.

    In LAN exam mode the request must also come from the IP that signed in. A copied
    session cookie alone therefore cannot submit from another machine.
    """
    session = get_session(request.cookies.get(SESSION_COOKIE))
    if not session:
        return None
    request_device_id = _verify_device_id(request.cookies.get(DEVICE_COOKIE))
    ip = client_ip(request)
    mismatches = []
    if request_device_id != session["device_id"]:
        mismatches.append("device")
    if _lan_exam_mode() and session.get("ip_address") and ip != session["ip_address"]:
        mismatches.append("ip")
    if mismatches:
        logger.warning(
            "Session rejected: presented from a different %s username=%s user_id=%s "
            "session_ip=%s request_ip=%s session_device_id=%s request_device_id=%s",
            "/".join(mismatches),
            session["username"],
            session["user_id"],
            session.get("ip_address", ""),
            ip,
            session["device_id"],
            request_device_id,
        )
        return None
    return session


def authenticated_session(request: Request):
    session = _bound_session(request)
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
    fingerprint = _browser_fingerprint(request)
    lan_mode = _lan_exam_mode()
    _reject_if_device_has_other_account(user["id"], user["username"], device_id, ip, fingerprint, lan_mode)
    new_alert = _record_login_and_start_session(response, user, device_id, ip, fingerprint, lan_mode)
    return {"user": user, "login_alert": new_alert}


def _session_alerts(request: Request, session):
    ip = client_ip(request)
    fingerprint = session.get("browser_fingerprint") or _browser_fingerprint(request)
    alerts = list_login_alerts_for_user(session["user_id"])
    if _lan_exam_mode() and ip != "unknown":
        # Show the warning only on the later seat, even when it copied the first seat's device cookie.
        return [
            alert for alert in alerts
            if alert["second_device_id"] == session["device_id"] and alert["second_ip_address"] == ip
        ]
    return [
        alert for alert in alerts
        if alert["second_device_id"] == session["device_id"]
        or (
            fingerprint
            and alert["second_ip_address"] == ip
            and alert.get("second_browser_fp") == fingerprint
        )
    ]


@app.get("/session")
def current_session(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    session = _bound_session(request)
    if not session:
        return {"user": None, "login_alerts": []}
    return {
        "user": {"id": session["user_id"], "username": session["username"]},
        "login_alerts": _session_alerts(request, session),
    }


@app.post("/login-alerts")
def login_alerts(request: Request):
    session = authenticated_session(request)
    return _session_alerts(request, session)


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
    ip = client_ip(request)
    fingerprint = _browser_fingerprint(request)
    if is_submission_blocked(
        session["user_id"],
        session.get("device_id", ""),
        ip,
        session.get("browser_fingerprint") or fingerprint,
        lan_mode=_lan_exam_mode(),
    ):
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
