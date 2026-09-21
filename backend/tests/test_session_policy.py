"""Defensive regression checks; database cases require the isolated Compose DB."""
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main
import session_security as security
from database import create_user, get_connection, hash_session_token, init_db


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("DEVICE_SECRET", "test-only-secret-" * 4)
    monkeypatch.setenv("EXAM_MODE", "true")
    monkeypatch.setenv("REGISTRATION_ENABLED", "false")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("ALLOW_INSECURE_HTTP", "false")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    monkeypatch.setattr(main, "resolve_device_name", lambda ip: "fixture-host")


def test_secure_defaults_and_exam_registration_override(monkeypatch):
    monkeypatch.delenv("EXAM_MODE")
    monkeypatch.setenv("REGISTRATION_ENABLED", "true")
    assert security.exam_mode()
    assert not security.registration_enabled()
    client = TestClient(main.app, base_url="https://testserver")
    assert client.get("/auth-config").json() == {"registration_enabled": False}
    assert client.post("/register", data={"username": "fixture", "password": "password"}).status_code == 403


def test_plain_http_rejected_and_untrusted_headers_ignored():
    client = TestClient(main.app, base_url="http://testserver")
    assert client.get("/auth-config").status_code == 400
    assert client.get("/auth-config", headers={"X-Forwarded-Proto": "https"}).status_code == 400
    assert TestClient(main.app, base_url="https://testserver").get("/auth-config").status_code == 200


def test_explicit_development_http_override(monkeypatch):
    monkeypatch.setenv("ALLOW_INSECURE_HTTP", "true")
    assert TestClient(main.app).get("/auth-config").status_code == 200


@pytest.fixture
def db():
    if os.getenv("OJ_INTEGRATION_TEST") != "1":
        pytest.skip("requires isolated MariaDB integration environment")
    assert os.getenv("MARIADB_HOST") == "db", "Never use a host database"
    init_db()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            for table in ("submission_audit", "security_events", "users"):
                cursor.execute(f"DELETE FROM {table}")
    return True


def user():
    return create_user("fixture_" + uuid4().hex[:14], "test-password")


def context(ip="192.0.2.10", device=None, fp="a" * 64):
    return {"ip_address": ip, "device_id": device or str(uuid4()), "browser_fingerprint": fp}


def rows(sql, args=()):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.fetchall()


def check(token, ctx):
    with security.security_transaction() as connection:
        return security.check_session(connection, token, ctx)


@pytest.mark.parametrize("field,value", [("device_id", ""), ("ip_address", "192.0.2.11"), ("browser_fingerprint", "b" * 64)])
def test_changed_request_context_revokes_every_session(db, field, value):
    u, ctx = user(), context()
    first = security.issue_session(u["id"], ctx)
    second = security.issue_session(u["id"], ctx)
    assert check(first, ctx)[1] is None
    assert check(first, {**ctx, field: value})[1] == 403
    assert check(first, ctx)[1] == check(second, ctx)[1] == 403
    assert security.issue_session(u["id"], ctx) is None
    assert len(rows("SELECT * FROM security_events WHERE reason='session_context_mismatch'")) == 1


def test_device_context_change_logged_and_blocks_all_sessions(db):
    u, ctx = user(), context()
    token = security.issue_session(u["id"], ctx, "first-host")
    assert security.issue_session(u["id"], {**ctx, "ip_address": "192.0.2.20"}, "second-host") is None
    events = rows("SELECT * FROM login_events ORDER BY id")
    assert len(events) == 2
    assert events[0]["device_name"] == "first-host"
    assert events[1]["device_name"] == "second-host"
    assert events[1]["outcome"] == "context_conflict"
    assert check(token, ctx)[1] == 403


def test_exam_ip_rule_ignores_client_identity_changes(db):
    first, second = user(), user()
    ctx = context()
    token = security.issue_session(first["id"], ctx)
    assert security.issue_session(second["id"], context(fp="b" * 64)) is None
    assert check(token, ctx)[1] == 403
    assert len(rows("SELECT * FROM users WHERE blocked_until > NOW()")) == 2


def test_separate_source_accounts_and_repeated_logins_allowed(db):
    first, second = user(), user()
    ctx = context()
    assert security.issue_session(first["id"], ctx)
    assert security.issue_session(first["id"], ctx)
    assert security.issue_session(second["id"], context(ip="192.0.2.20"))
    assert len(rows("SELECT * FROM login_events")) == 3
    assert rows("SELECT * FROM security_events") == ()


def test_parallel_account_claims_cannot_both_succeed(db):
    ids = [user()["id"], user()["id"]]
    contexts = [context(fp="a" * 64), context(fp="b" * 64)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        tokens = list(pool.map(lambda pair: security.issue_session(*pair), zip(ids, contexts)))
    assert sum(token is not None for token in tokens) == 1
    assert len(rows("SELECT * FROM users WHERE blocked_until > NOW()")) == 2
    assert not rows("SELECT * FROM sessions WHERE revoked_at IS NULL")


def test_legacy_sessions_require_login_and_migration_is_repeatable(db):
    u = user()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO sessions (token_hash,user_id,device_id,expires_at) VALUES (%s,%s,%s,NOW()+INTERVAL 1 HOUR)", (hash_session_token("legacy"), u["id"], str(uuid4())))
    init_db()
    init_db()
    assert check("legacy", context())[1] == 401
    assert len(rows("SELECT * FROM sessions")) == 1


def test_expired_blocks_allow_new_login_but_never_revive_revoked_tokens(db):
    u, ctx = user(), context()
    token = security.issue_session(u["id"], ctx)
    assert check(token, {**ctx, "device_id": ""})[1] == 403
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE users SET blocked_until=NOW()-INTERVAL 1 SECOND")
            cursor.execute("UPDATE login_events SET logged_in_at=NOW()-INTERVAL 4 HOUR")
    assert check(token, ctx)[1] == 403
    assert security.issue_session(u["id"], ctx)


def api_client(monkeypatch, ip="192.0.2.10"):
    monkeypatch.setattr(main, "client_ip", lambda request: ip)
    return TestClient(main.app, base_url="https://testserver", headers={"X-Client-Fingerprint": "fixture"})


def api_login(client, u):
    return client.post("/login", data={"username": u["username"], "password": "test-password"})


def test_registration_uses_login_policy_and_records_attempts(db, monkeypatch):
    monkeypatch.setenv("EXAM_MODE", "false")
    monkeypatch.setenv("REGISTRATION_ENABLED", "true")
    client = api_client(monkeypatch)
    first = client.post("/register", data={"username": "fixture_one", "password": "test-password"})
    assert first.status_code == 200
    assert all("Secure" in c and "HttpOnly" in c for c in first.headers.get_list("set-cookie"))
    second = client.post("/register", data={"username": "fixture_two", "password": "test-password"})
    assert second.status_code == 403
    assert len(rows("SELECT * FROM login_events")) == 2
    assert client.get("/problems").status_code == 403


def test_protected_routes_and_submission_provenance(db, monkeypatch):
    client = api_client(monkeypatch)
    assert client.get("/problems").status_code == 401
    u = user()
    assert api_login(client, u).status_code == 200
    assert client.get("/problems").status_code == 200
    assert client.get("/session").json()["user"] == u
    monkeypatch.setattr(main, "judge_submission", lambda *args: {"status": "AC"})
    fields = {"language": "c", "code": "fixture", "problem_id": "1002"}
    assert client.post("/submit", data=fields).status_code == 200
    saved = rows("SELECT * FROM submissions")[0]
    assert saved["ip_address"] == "192.0.2.10"
    assert saved["session_hash"] == hash_session_token(client.cookies["oj_session"])
    assert saved["device_id"] == main._verify_device_id(client.cookies["oj_device"])
    assert len(saved["browser_fingerprint"]) == 64
    assert client.post("/submit", data=fields).status_code == 429
    client.cookies.delete("oj_device")
    for path, method in [("/session", "get"), ("/problems", "get"), ("/submissions", "post"), ("/login-alerts", "post")]:
        assert getattr(client, method)(path).status_code == 403
    assert client.post("/submit", data=fields).status_code == 403
    audits = rows("SELECT * FROM submission_audit ORDER BY id")
    assert [a["outcome"] for a in audits] == ["accepted", "denied_429", "denied_403"]
    assert audits[-1]["device_id"] == ""
    assert len(rows("SELECT * FROM submissions")) == 1


def test_conflict_during_judging_cannot_save_accepted_result(db, monkeypatch):
    client, u = api_client(monkeypatch), user()
    assert api_login(client, u).status_code == 200
    def judge(*args):
        assert security.issue_session(u["id"], context(ip="192.0.2.90")) is None
        return {"status": "AC"}
    monkeypatch.setattr(main, "judge_submission", judge)
    assert client.post("/submit", data={"language": "c", "code": "fixture", "problem_id": "1002"}).status_code == 403
    assert not rows("SELECT * FROM submissions")
    assert rows("SELECT outcome FROM submission_audit")[0]["outcome"] == "denied_403"


def test_context_conflict_blocks_other_account_at_observed_source(db):
    first, second = user(), user()
    a, b = context(ip="192.0.2.21"), context(ip="192.0.2.22")
    one = security.issue_session(first["id"], a)
    two = security.issue_session(second["id"], b)
    assert check(one, b)[1] == 403
    assert check(two, b)[1] == 403
    assert len(rows("SELECT * FROM users WHERE blocked_until > NOW()")) == 2


def test_expired_and_unknown_sessions_are_not_authenticated(db):
    u, ctx = user(), context()
    token = security.issue_session(u["id"], ctx)
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE sessions SET expires_at=NOW()-INTERVAL 1 SECOND")
    assert check(token, ctx)[1] == 401
    assert check("unknown-fixture", ctx)[1] == 401
    assert security.issue_session(u["id"], context(ip="unknown")) is None


def test_incomplete_submission_form_is_audited(db, monkeypatch):
    client = api_client(monkeypatch)
    response = client.post("/submit", data={"problem_id": "1002"})
    assert response.status_code == 422
    audit = rows("SELECT * FROM submission_audit")[0]
    assert audit["outcome"] == "denied_422"
    assert audit["ip_address"] == "192.0.2.10"
    assert audit["session_hash"] is None
