"""Explicit database integration check; removes only its unique fixture user."""
import os
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import create_user, get_connection, init_db, record_login


def run():
    assert os.getenv("OJ_INTEGRATION_TEST") == "1", "Requires explicit integration-test opt-in"
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,user_id,ip_address,device_id,browser_fingerprint,logged_in_at FROM login_events")
            existing = {row["id"]: row for row in cursor.fetchall()}
    init_db()
    init_db()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,user_id,ip_address,device_id,browser_fingerprint,logged_in_at FROM login_events")
            current = {row["id"]: row for row in cursor.fetchall()}
            assert all(current.get(key) == row for key, row in existing.items())
            cursor.execute("SHOW COLUMNS FROM login_events LIKE 'device_name'")
            column = cursor.fetchone()
            assert column["Type"] == "varchar(253)" and column["Default"] == ""
    print("PASS additive, repeatable migration preserves existing login events")
    user = create_user("device_name_test_" + uuid4().hex[:12], uuid4().hex)
    uid = user["id"]

    def event():
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM login_events WHERE user_id=%s ORDER BY id", (uid,))
                rows = cursor.fetchall()
                assert len(rows) == 1
                return rows[0]

    try:
        device = str(uuid4())
        record_login(uid, "192.0.2.10", device)
        initial = event()
        assert initial["device_name"] == ""
        print("PASS missing name stores empty value")
        record_login(uid, "192.0.2.11", device, device_name="different-ip-host")
        assert event()["device_name"] == ""
        print("PASS changed IP does not relabel an old event")
        record_login(uid, "192.0.2.10", device, device_name="ganges-desktop")
        enriched = event()
        assert enriched["device_name"] == "ganges-desktop"
        assert enriched["id"] == initial["id"] and enriched["logged_in_at"] == initial["logged_in_at"]
        print("PASS repeat login enriches the same event without changing timestamp")
        record_login(uid, "192.0.2.10", device, device_name="renamed-host")
        assert event()["device_name"] == "ganges-desktop"
        print("PASS existing event name is preserved")
        record_login(uid, "192.0.2.12", str(uuid4()), device_name="new-device")
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT device_name FROM login_events WHERE user_id=%s ORDER BY id DESC LIMIT 1", (uid,))
                assert cursor.fetchone()["device_name"] == "new-device"
        print("PASS new device login stores its name")
    finally:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM users WHERE id=%s", (uid,))
        print("Fixture user and dependent rows removed")


if __name__ == "__main__":
    run()
