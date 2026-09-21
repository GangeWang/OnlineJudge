"""HTTPS smoke test against isolated Nginx, MariaDB and the Docker judge."""
import os
import ssl
import sys
from pathlib import Path
from uuid import uuid4

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import create_user, get_connection, hash_session_token


def run():
    assert os.getenv("OJ_INTEGRATION_TEST") == "1"
    assert os.getenv("MARIADB_HOST") == "db", "Never run against the host database"
    tls = ssl.create_default_context(cafile="/test-ca.pem")
    results = []

    def check(name, condition):
        assert condition, name
        results.append(name)
        print("PASS " + name, flush=True)

    def row(sql, args=()):
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, args)
                return cursor.fetchone()

    # No credential-bearing request is sent over HTTP.
    r = httpx.get("http://nginx/api/auth-config", follow_redirects=False)
    check("HTTP redirects to HTTPS", r.status_code == 308 and r.headers["location"].startswith("https://"))
    check("backend refuses unencrypted direct requests", httpx.get("http://127.0.0.1:8000/auth-config").status_code == 400)
    with httpx.Client(base_url="https://nginx/api", verify=tls, timeout=90,
                      headers={"X-Client-Fingerprint": "https-fixture"}) as client:
        r = client.get("/auth-config")
        check("verified TLS, HSTS and closed registration", r.status_code == 200 and not r.json()["registration_enabled"] and "max-age" in r.headers["strict-transport-security"])
        check("anonymous problem descriptions denied", client.get("/problems").status_code == 401)
        check("exam registration denied", client.post("/register", data={"username": "fixture", "password": "test-password"}).status_code == 403)
        u = create_user("tls_fixture_" + uuid4().hex[:12], "test-password")
        try:
            creds = {"username": u["username"], "password": "test-password"}
            r = client.post("/login", data=creds)
            check("TLS login with Secure and HttpOnly cookies", r.status_code == 200 and len(r.headers.get_list("set-cookie")) == 2 and all("Secure" in c and "HttpOnly" in c for c in r.headers.get_list("set-cookie")))
            check("authenticated problems and restored session", client.get("/problems").status_code == 200 and client.get("/session").json()["user"] == u)
            check("repeat login succeeds and adds audit event", client.post("/login", data=creds).status_code == 200 and row("SELECT COUNT(*) AS n FROM login_events WHERE user_id=%s", (u["id"],))["n"] == 2)
            code = '#include <stdio.h>\nint main(){int a,b;if(scanf("%d%d",&a,&b)==2)printf("%d",a+b);return 0;}'
            fields = {"language": "c", "problem_id": "1002", "code": code}
            r = client.post("/submit", data=fields)
            check("real Docker C judge returns AC over TLS", r.status_code == 200 and r.json().get("status") == "AC")
            stored = row("SELECT * FROM submissions WHERE id=%s", (r.json()["submission_id"],))
            event = row("SELECT * FROM login_events WHERE user_id=%s ORDER BY id DESC LIMIT 1", (u["id"],))
            check("submission stores observed IP, device, fingerprint and token hash", stored["ip_address"] == event["ip_address"] and stored["device_id"] == event["device_id"] and stored["browser_fingerprint"] == event["browser_fingerprint"] and stored["session_hash"] == hash_session_token(client.cookies["oj_session"]))
            check("history and rate limit remain functional", len(client.post("/submissions").json()) == 1 and client.post("/submit", data=fields).status_code == 429)
            # Rate limiting was checked above; advance only fixture timestamps
            # between judge cases so the regression suite remains fast.
            for label, language, source, expected in (
                ("C++ AC", "cpp", '#include <iostream>\nint main(){int a,b;std::cin>>a>>b;std::cout<<a+b;}', "AC"),
                ("wrong answer", "c", '#include <stdio.h>\nint main(){puts("wrong");}', "WA"),
                ("compile error", "c", 'int main( {', "CE"),
            ):
                with get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("UPDATE submission_attempts SET attempted_at=NOW()-INTERVAL 1 MINUTE WHERE user_id=%s", (u["id"],))
                judged = client.post("/submit", data={**fields, "language": language, "code": source})
                check("real Docker judge " + label, judged.status_code == 200 and judged.json().get("status") == expected)
            check("all judge results appear in history", len(client.post("/submissions").json()) == 4)
            with httpx.Client(base_url="https://nginx/api", verify=tls, timeout=30) as second:
                check("conflicting login denied", second.post("/login", data=creds).status_code == 403)
            check("earlier session also blocked", client.get("/session").status_code == 403 and client.post("/submit", data=fields).status_code == 403)
            check("denied submit audited and not saved as accepted", row("SELECT outcome FROM submission_audit WHERE user_id=%s ORDER BY id DESC LIMIT 1", (u["id"],))["outcome"] == "denied_403" and row("SELECT COUNT(*) AS n FROM submissions WHERE user_id=%s", (u["id"],))["n"] == 4)
        finally:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    for table in ("security_events", "submission_audit"):
                        cursor.execute(f"DELETE FROM {table} WHERE user_id=%s", (u["id"],))
                    cursor.execute("DELETE FROM users WHERE id=%s", (u["id"],))
    print(f"{len(results)} HTTPS integration checks passed")


if __name__ == "__main__":
    run()
