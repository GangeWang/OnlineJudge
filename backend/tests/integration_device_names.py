"""Device names remain audit labels; requires the isolated test database."""
import os
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import create_user, get_connection, init_db
from session_security import issue_session


def run():
    assert os.getenv("OJ_INTEGRATION_TEST") == "1"
    assert os.getenv("MARIADB_HOST") == "db", "Never run against the host database"
    init_db()
    init_db()
    u = create_user("names_fixture_" + uuid4().hex[:12], uuid4().hex)
    ctx = {"ip_address": "192.0.2.201", "device_id": str(uuid4()), "browser_fingerprint": "a" * 64}
    try:
        assert issue_session(u["id"], ctx, "first-name")
        assert issue_session(u["id"], ctx, "updated-name")
        assert issue_session(u["id"], {**ctx, "ip_address": "192.0.2.202"}, "first-name") is None
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT device_name, outcome FROM login_events WHERE user_id=%s ORDER BY id", (u["id"],))
                events = cursor.fetchall()
        assert [e["device_name"] for e in events] == ["first-name", "updated-name", "first-name"]
        assert [e["outcome"] for e in events] == ["accepted", "accepted", "context_conflict"]
        print("PASS every login preserves its observed name; matching names cannot bypass context policy")
    finally:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM security_events WHERE user_id=%s", (u["id"],))
                cursor.execute("DELETE FROM users WHERE id=%s", (u["id"],))


if __name__ == "__main__":
    run()
