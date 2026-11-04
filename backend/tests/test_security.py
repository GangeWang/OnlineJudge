import importlib
import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
main = importlib.import_module("main")


def request(client, headers=(), cookies=None):
    raw_headers = [(name.lower().encode(), value.encode()) for name, value in headers]
    if cookies:
        raw_headers.append((b"cookie", cookies.encode()))
    return Request({"type": "http", "client": client, "headers": raw_headers})


@pytest.fixture(autouse=True)
def secure_environment(monkeypatch):
    monkeypatch.setenv("DEVICE_SECRET", "a" * 32)
    monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    monkeypatch.delenv("LAN_EXAM_MODE", raising=False)
    monkeypatch.delenv("ALLOW_REGISTRATION", raising=False)


def test_device_secret_has_no_insecure_default(monkeypatch):
    monkeypatch.delenv("DEVICE_SECRET")
    with pytest.raises(RuntimeError):
        main._device_secret()


def test_unsigned_device_cookie_is_replaced_instead_of_migrated():
    forged_id = "00000000-0000-0000-0000-000000000001"
    response = Response()
    actual_id = main._device_id(
        request(("127.0.0.1", 1234), cookies=f"{main.DEVICE_COOKIE}={forged_id}"),
        response,
    )

    assert actual_id != forged_id
    assert main._verify_device_id(response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]) == actual_id
    assert "Secure" in response.headers["set-cookie"]


def test_tampered_signed_device_cookie_is_rejected():
    signed = main._sign_device_id("00000000-0000-0000-0000-000000000001")
    assert main._verify_device_id(signed) is not None
    assert main._verify_device_id(signed[:-1] + ("0" if signed[-1] != "0" else "1")) is None


def test_private_client_cannot_forge_forwarded_ip():
    forged = request(("10.0.0.25", 1234), [("x-real-ip", "203.0.113.7")])
    assert main.client_ip(forged) == "10.0.0.25"


def test_only_configured_proxy_can_supply_real_ip(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.10/32")
    proxied = request(("10.0.0.10", 1234), [("x-real-ip", "203.0.113.7")])
    assert main.client_ip(proxied) == "203.0.113.7"


@pytest.mark.parametrize("signature", ["é", "a" * 63, "a" * 65, "g" * 64])
def test_malformed_signature_is_rejected_without_exception(signature):
    assert main._verify_device_id(
        "00000000-0000-0000-0000-000000000001." + signature
    ) is None


def test_docker_proxy_preserves_lan_ip_and_ignores_forwarded_chain(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "172.18.0.1/32")
    proxied = request(("172.18.0.1", 1234), [
        ("x-real-ip", "192.168.137.25"),
        ("x-forwarded-for", "203.0.113.99"),
    ])
    assert main.client_ip(proxied) == "192.168.137.25"
    other_container = request(("172.18.0.25", 1234), [
        ("x-real-ip", "192.168.137.25"),
    ])
    assert main.client_ip(other_container) == "172.18.0.25"


SEAT_IP = "192.168.137.21"
OTHER_SEAT_IP = "192.168.137.22"
DEVICE_A = "00000000-0000-4000-8000-00000000000a"
DEVICE_B = "00000000-0000-4000-8000-00000000000b"


def session_row(device_id=DEVICE_A, ip=SEAT_IP):
    return {
        "user_id": 7,
        "username": "examinee",
        "device_id": device_id,
        "browser_fingerprint": "",
        "ip_address": ip,
    }


def session_request(device_id, client_ip=SEAT_IP):
    cookies = f"{main.SESSION_COOKIE}=token"
    if device_id:
        cookies += f"; {main.DEVICE_COOKIE}={main._sign_device_id(device_id)}"
    return request((client_ip, 1234), cookies=cookies)


def refuse_database(*_args, **_kwargs):
    raise AssertionError("must not touch the database")


def test_session_cookie_is_rejected_without_the_device_cookie_it_was_issued_to(monkeypatch):
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    assert main._bound_session(session_request(DEVICE_B)) is None
    assert main._bound_session(session_request(None)) is None
    assert main._bound_session(session_request(DEVICE_A))["user_id"] == 7


def test_lan_exam_mode_binds_session_to_login_ip(monkeypatch):
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    copied_to_other_seat = session_request(DEVICE_A, OTHER_SEAT_IP)
    # NAT-friendly default: the IP is not part of the session identity.
    assert main._bound_session(copied_to_other_seat) is not None
    monkeypatch.setenv("LAN_EXAM_MODE", "true")
    assert main._bound_session(copied_to_other_seat) is None
    assert main._bound_session(session_request(DEVICE_A)) is not None


def test_lan_exam_mode_keeps_sessions_created_before_ip_binding(monkeypatch):
    monkeypatch.setenv("LAN_EXAM_MODE", "true")
    monkeypatch.setattr(main, "get_session", lambda token: session_row(ip=""))
    assert main._bound_session(session_request(DEVICE_A, OTHER_SEAT_IP)) is not None


@pytest.mark.parametrize("value,expected", [
    (None, False), ("", False), ("false", False), ("0", False), ("off", False),
    ("true", True), ("1", True), ("yes", True), ("TRUE", True),
])
def test_lan_exam_mode_flag(monkeypatch, value, expected):
    if value is not None:
        monkeypatch.setenv("LAN_EXAM_MODE", value)
    assert main._lan_exam_mode() is expected


def test_closed_registration_is_refused_before_touching_the_database(monkeypatch):
    monkeypatch.setenv("ALLOW_REGISTRATION", "false")
    monkeypatch.setattr(main, "find_recent_other_user_on_device", refuse_database)
    monkeypatch.setattr(main, "create_user", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.register(request((SEAT_IP, 1234)), Response(), "newuser", "password")
    assert refused.value.status_code == 403


def test_registration_obeys_one_account_per_device_before_creating_the_account(monkeypatch):
    checked = {}

    def other_account(user_id, device_id, ip, fingerprint, lan_mode=False):
        checked.update(user_id=user_id, ip=ip, lan_mode=lan_mode)
        return {"id": 3, "username": "first-account"}

    monkeypatch.setenv("LAN_EXAM_MODE", "true")
    monkeypatch.setattr(main, "find_recent_other_user_on_device", other_account)
    monkeypatch.setattr(main, "create_user", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.register(request((SEAT_IP, 1234)), Response(), "newuser", "password")
    assert refused.value.status_code == 403
    assert checked == {"user_id": main.NO_USER_ID, "ip": SEAT_IP, "lan_mode": True}
