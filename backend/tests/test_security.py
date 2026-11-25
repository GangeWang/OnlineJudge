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
    monkeypatch.delenv("ADMIN_USERNAMES", raising=False)
    # Practice mode by default; tests that need an exam patch their own schedule.
    monkeypatch.setattr(main, "get_exam_schedule", lambda: {
        "start_at": None, "end_at": None, "updated_by": "", "updated_at": None,
    })


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


SESSION_CREATED = 2_000_000_000  # epoch seconds, year 2033


def session_row(device_id=DEVICE_A, ip=SEAT_IP, created_epoch=SESSION_CREATED):
    return {
        "user_id": 7,
        "username": "examinee",
        "device_id": device_id,
        "browser_fingerprint": "",
        "ip_address": ip,
        "created_epoch": created_epoch,
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


def test_lan_exam_mode_rejects_sessions_created_before_ip_binding(monkeypatch):
    monkeypatch.setattr(main, "get_session", lambda token: session_row(ip=""))
    assert main._bound_session(session_request(DEVICE_A)) is not None
    monkeypatch.setenv("LAN_EXAM_MODE", "true")
    assert main._bound_session(session_request(DEVICE_A)) is None


def test_logout_deletes_own_session_and_clears_cookie(monkeypatch):
    deleted = []
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "delete_session", deleted.append)
    response = Response()
    assert main.logout(session_request(DEVICE_A), response) == {"ok": True}
    assert deleted == ["token"]
    assert response.headers["set-cookie"].startswith(f'{main.SESSION_COOKIE}=""')
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_logout_from_another_device_does_not_end_the_owners_session(monkeypatch):
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "delete_session", refuse_database)
    response = Response()
    main.logout(session_request(DEVICE_B), response)
    assert "Max-Age=0" in response.headers["set-cookie"]


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

    def other_account(user_id, device_id, ip, fingerprint, lan_mode=False, ignore_usernames=(), since=None):
        checked.update(user_id=user_id, ip=ip, lan_mode=lan_mode, ignored=set(ignore_usernames))
        # Practice mode: the window starts three hours ago.
        assert abs(since - (main._utc_now() - main.PRACTICE_WINDOW).replace(tzinfo=main.timezone.utc).timestamp()) < 5
        return {"id": 3, "username": "first-account"}

    monkeypatch.setenv("LAN_EXAM_MODE", "true")
    monkeypatch.setenv("ADMIN_USERNAMES", "teacher")
    monkeypatch.setattr(main, "find_recent_other_user_on_device", other_account)
    monkeypatch.setattr(main, "create_user", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.register(request((SEAT_IP, 1234)), Response(), "newuser", "password")
    assert refused.value.status_code == 403
    # Admin logins never count against other accounts.
    assert checked == {"user_id": main.NO_USER_ID, "ip": SEAT_IP, "lan_mode": True, "ignored": {"teacher"}}


@pytest.mark.parametrize("username", ["teacher", "TEACHER", "Teacher", " teacher "])
def test_configured_admin_names_cannot_be_self_registered(monkeypatch, username):
    monkeypatch.setenv("ADMIN_USERNAMES", "Teacher")
    monkeypatch.setattr(main, "find_recent_other_user_on_device", refuse_database)
    monkeypatch.setattr(main, "create_user", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.register(request((SEAT_IP, 1234)), Response(), username, "password")
    assert refused.value.status_code == 403


def test_admin_is_not_limited_to_one_account_per_device(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAMES", "teacher")
    monkeypatch.setattr(main, "find_recent_other_user_on_device", refuse_database)
    main._reject_if_device_has_other_account(1, "teacher", DEVICE_A, SEAT_IP, "", lan_mode=True)


from datetime import datetime, timedelta

EXAM_START = datetime(2026, 11, 5, 1, 0)  # naive UTC
EXAM_END = datetime(2026, 11, 5, 3, 0)


@pytest.mark.parametrize("now,phase", [
    (EXAM_START - timedelta(seconds=1), main.EXAM_NOT_STARTED),
    (EXAM_START, main.EXAM_RUNNING),
    (EXAM_END - timedelta(seconds=1), main.EXAM_RUNNING),
    (EXAM_END, main.EXAM_ENDED),
])
def test_exam_phase_boundaries(now, phase):
    assert main.exam_phase(EXAM_START, EXAM_END, now) == phase


def test_no_schedule_is_open_practice():
    assert main.exam_phase(None, None, EXAM_START) == main.EXAM_OPEN


@pytest.mark.parametrize("value,expected", [
    ("2026-11-05T01:00:00Z", EXAM_START),
    ("2026-11-05T09:00:00+08:00", EXAM_START),
    ("2026-11-05T01:00:00.000Z", EXAM_START),
])
def test_exam_time_is_stored_as_utc(value, expected):
    assert main._parse_exam_time(value) == expected


@pytest.mark.parametrize("value", ["2026-11-05T09:00", "tomorrow", ""])
def test_exam_time_without_offset_or_malformed_is_rejected(value):
    with pytest.raises(HTTPException) as rejected:
        main._parse_exam_time(value)
    assert rejected.value.status_code == 400


def test_admins_come_only_from_configuration(monkeypatch):
    assert not main._is_admin("Gange")
    monkeypatch.setenv("ADMIN_USERNAMES", " Gange , teacher ")
    assert main._is_admin("Gange") and main._is_admin("teacher")
    assert not main._is_admin("gange") and not main._is_admin("")


def schedule(start, end):
    return lambda: {"start_at": start, "end_at": end, "updated_by": "", "updated_at": None}


def test_problems_are_public_only_without_an_exam(monkeypatch):
    monkeypatch.setattr(main, "get_exam_schedule", schedule(None, None))
    monkeypatch.setattr(main, "get_session", refuse_database)
    assert isinstance(main.list_problems(request((SEAT_IP, 1234))), list)


@pytest.mark.parametrize("start,end", [
    (datetime(2099, 1, 1), datetime(2099, 1, 2)),  # not started
    (datetime(2000, 1, 1), datetime(2099, 1, 1)),  # running
    (datetime(2000, 1, 1), datetime(2000, 1, 2)),  # ended
])
def test_exam_problems_require_login(monkeypatch, start, end):
    monkeypatch.setattr(main, "get_exam_schedule", schedule(start, end))
    with pytest.raises(HTTPException) as refused:
        main.list_problems(request((SEAT_IP, 1234)))
    assert refused.value.status_code == 401


def test_problems_hidden_before_start_except_for_admins(monkeypatch):
    monkeypatch.setattr(main, "get_exam_schedule", schedule(datetime(2099, 1, 1), datetime(2099, 1, 2)))
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    with pytest.raises(HTTPException) as refused:
        main.list_problems(session_request(DEVICE_A))
    assert refused.value.status_code == 403
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    assert isinstance(main.list_problems(session_request(DEVICE_A)), list)


@pytest.mark.parametrize("start,end,detail", [
    (datetime(2099, 1, 1), datetime(2099, 1, 2), "考試尚未開始，無法提交"),
    (datetime(2000, 1, 1), datetime(2000, 1, 2), "考試已結束，無法提交"),
])
def test_submissions_closed_outside_the_window(monkeypatch, start, end, detail):
    monkeypatch.setattr(main, "get_exam_schedule", schedule(start, end))
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "is_submission_blocked", refuse_database)
    monkeypatch.setattr(main, "record_submission_attempt", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.submit(session_request(DEVICE_A), "c", "int main(){}", "1002")
    assert (refused.value.status_code, refused.value.detail) == (403, detail)


def test_only_admins_can_change_the_exam(monkeypatch):
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "set_exam_schedule", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.update_admin_exam(session_request(DEVICE_A), "2026-11-05T01:00:00Z", "2026-11-05T03:00:00Z")
    assert refused.value.status_code == 403


@pytest.mark.parametrize("start,end", [
    ("2026-11-05T03:00:00Z", "2026-11-05T01:00:00Z"),
    ("2026-11-05T01:00:00Z", "2026-11-05T01:00:00Z"),
    ("2026-11-05T01:00:00Z", ""),
])
def test_invalid_exam_window_is_rejected(monkeypatch, start, end):
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "set_exam_schedule", refuse_database)
    with pytest.raises(HTTPException) as rejected:
        main.update_admin_exam(session_request(DEVICE_A), start, end)
    assert rejected.value.status_code == 400


def test_admin_login_raises_no_cross_device_alert(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAMES", "teacher")
    captured = {}

    def record_login(*args, **kwargs):
        captured.update(kwargs)
        return [], {"second_ip_address": OTHER_SEAT_IP}

    monkeypatch.setattr(main, "record_login", record_login)
    monkeypatch.setattr(main, "resolve_device_name", lambda ip: "")
    monkeypatch.setattr(main, "create_session", lambda *args, **kwargs: "token")
    alert = main._record_login_and_start_session(
        Response(), {"id": 1, "username": "teacher"}, DEVICE_A, SEAT_IP, "", False,
    )
    assert alert is None
    assert captured["raise_alerts"] is False


def test_admin_submissions_are_never_blocked_by_cross_device_alerts(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    monkeypatch.setattr(main, "get_exam_schedule", schedule(None, None))
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "is_submission_blocked", refuse_database)
    monkeypatch.setattr(main, "record_submission_attempt", lambda *args: 0)
    monkeypatch.setattr(main, "judge_submission", lambda *args: {"status": "AC"})
    monkeypatch.setattr(main, "save_submission", lambda *args: 9)
    assert main.submit(session_request(DEVICE_A), "c", "code", "1002") == {"status": "AC", "submission_id": 9}


def test_admin_sees_no_cross_device_warnings(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    monkeypatch.setattr(main, "list_login_alerts_for_user", refuse_database)
    assert main._session_alerts(session_request(DEVICE_A), session_row()) == []


def epoch(value):
    return value.replace(tzinfo=main.timezone.utc).timestamp()


@pytest.mark.parametrize("now,expected", [
    # Exam 01:00-03:00 UTC: the window opens one hour before the start and closes at the end.
    (EXAM_START - timedelta(hours=1, seconds=1), None),
    (EXAM_START - timedelta(hours=1), epoch(EXAM_START - timedelta(hours=1))),
    (EXAM_START + timedelta(minutes=30), epoch(EXAM_START - timedelta(hours=1))),
    (EXAM_END - timedelta(seconds=1), epoch(EXAM_START - timedelta(hours=1))),
    (EXAM_END, None),
])
def test_anti_cheat_window_follows_the_exam(now, expected):
    assert main.anti_cheat_since(EXAM_START, EXAM_END, now) == expected


def test_anti_cheat_window_is_three_hours_in_practice_mode():
    now = datetime(2026, 11, 5, 12, 0)
    assert main.anti_cheat_since(None, None, now) == epoch(now - timedelta(hours=3))


def test_submissions_not_blocked_when_the_window_is_closed(monkeypatch):
    # Exam ended (window closed): no device rules; admins may still submit to test problems.
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    monkeypatch.setattr(main, "get_exam_schedule", schedule(datetime(2000, 1, 1), datetime(2000, 1, 2)))
    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "is_submission_blocked", refuse_database)
    monkeypatch.setattr(main, "find_recent_other_user_on_device", refuse_database)
    monkeypatch.setattr(main, "record_submission_attempt", lambda *args: 0)
    monkeypatch.setattr(main, "judge_submission", lambda *args: {"status": "AC"})
    monkeypatch.setattr(main, "save_submission", lambda *args: 9)
    assert main.submit(session_request(DEVICE_A), "c", "code", "1002")["status"] == "AC"
    monkeypatch.delenv("ADMIN_USERNAMES")
    main._reject_if_device_has_other_account(7, "examinee", DEVICE_A, SEAT_IP, "", lan_mode=True)


RUNNING_EXAM = (datetime(2000, 1, 1), datetime(2099, 1, 1))
RUNNING_WINDOW_OPENS = datetime(1999, 12, 31, 23, 0)  # one hour before the start


@pytest.mark.parametrize("seconds_after_opening,accepted", [
    (None, False),  # no creation time: cannot be shown to be inside the window
    (-1, False),
    (0, True),
    (3600, True),
])
def test_session_opened_before_the_exam_window_is_rejected_during_the_exam(monkeypatch, seconds_after_opening, accepted):
    created = None if seconds_after_opening is None else epoch(RUNNING_WINDOW_OPENS) + seconds_after_opening
    monkeypatch.setattr(main, "get_exam_schedule", schedule(*RUNNING_EXAM))
    monkeypatch.setattr(main, "get_session", lambda token: session_row(created_epoch=created))
    assert (main._bound_session(session_request(DEVICE_A)) is not None) == accepted


@pytest.mark.parametrize("start,end", [
    (None, None),  # practice mode: the window slides, sessions are not tied to it
    (datetime(2099, 1, 1), datetime(2099, 1, 2)),  # more than an hour before the start
    (datetime(2000, 1, 1), datetime(2000, 1, 2)),  # ended
])
def test_old_sessions_stay_valid_outside_an_exam_window(monkeypatch, start, end):
    monkeypatch.setattr(main, "get_exam_schedule", schedule(start, end))
    monkeypatch.setattr(main, "get_session", lambda token: session_row(created_epoch=0))
    assert main._bound_session(session_request(DEVICE_A)) is not None


def test_admin_session_survives_the_exam_window_opening(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    monkeypatch.setattr(main, "get_exam_schedule", schedule(*RUNNING_EXAM))
    monkeypatch.setattr(main, "get_session", lambda token: session_row(created_epoch=0))
    assert main._bound_session(session_request(DEVICE_A)) is not None


def stub_submission(monkeypatch, conflict):
    calls = []

    def exam_submission_conflict(*args, **kwargs):
        calls.append((args, kwargs))
        return conflict

    monkeypatch.setattr(main, "get_session", lambda token: session_row())
    monkeypatch.setattr(main, "is_submission_blocked", lambda *args, **kwargs: False)
    monkeypatch.setattr(main, "exam_submission_conflict", exam_submission_conflict)
    monkeypatch.setattr(main, "record_submission_attempt", lambda *args: 0)
    monkeypatch.setattr(main, "judge_submission", lambda *args: {"status": "AC"})
    monkeypatch.setattr(main, "save_submission", lambda *args: 9)
    return calls


@pytest.mark.parametrize("conflict,status,detail", [
    (main.RELOGIN, 401, "登入狀態已失效，請重新登入"),
    (main.CROSS_DEVICE, 403, "偵測到本場考試期間有異地登入，暫時無法提交答案"),
    (main.MULTI_ACCOUNT, 403, "此裝置本場考試期間已登入其他帳號，暫時無法提交答案"),
])
def test_exam_submission_is_refused_on_a_login_history_conflict(monkeypatch, conflict, status, detail):
    monkeypatch.setenv("ADMIN_USERNAMES", "teacher")
    monkeypatch.setenv("LAN_EXAM_MODE", "true")
    monkeypatch.setattr(main, "get_exam_schedule", schedule(*RUNNING_EXAM))
    calls = stub_submission(monkeypatch, conflict)
    monkeypatch.setattr(main, "record_submission_attempt", refuse_database)
    with pytest.raises(HTTPException) as refused:
        main.submit(session_request(DEVICE_A), "c", "code", "1002")
    assert (refused.value.status_code, refused.value.detail) == (status, detail)
    args, kwargs = calls[0]
    assert args[:3] == (7, DEVICE_A, SEAT_IP)
    assert kwargs == {"lan_mode": True, "ignore_usernames": {"teacher"}, "since": epoch(RUNNING_WINDOW_OPENS)}


def test_exam_submission_passes_without_a_conflict(monkeypatch):
    monkeypatch.setattr(main, "get_exam_schedule", schedule(*RUNNING_EXAM))
    calls = stub_submission(monkeypatch, None)
    assert main.submit(session_request(DEVICE_A), "c", "code", "1002")["status"] == "AC"
    assert len(calls) == 1


def test_login_history_check_is_for_examinees_during_an_exam_only(monkeypatch):
    # Practice mode: the window slides, so an old login legitimately falls out of it.
    monkeypatch.setattr(main, "get_exam_schedule", schedule(None, None))
    stub_submission(monkeypatch, None)
    monkeypatch.setattr(main, "exam_submission_conflict", refuse_database)
    assert main.submit(session_request(DEVICE_A), "c", "code", "1002")["status"] == "AC"
    # Administrators are exempt from the device rules during the exam as well.
    monkeypatch.setenv("ADMIN_USERNAMES", "examinee")
    monkeypatch.setattr(main, "get_exam_schedule", schedule(*RUNNING_EXAM))
    assert main.submit(session_request(DEVICE_A), "c", "code", "1002")["status"] == "AC"
