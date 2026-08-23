import hashlib
import os
from contextlib import contextmanager
from datetime import datetime
from time import sleep

import pymysql
from pymysql.cursors import DictCursor

DB_CONFIG = {
    "host": os.getenv("MARIADB_HOST", "host.docker.internal"),
    "port": int(os.getenv("MARIADB_PORT", "3306")),
    "user": os.getenv("MARIADB_USER", "onlinejudge"),
    "password": os.getenv("MARIADB_PASSWORD", "onlinejudge"),
    "database": os.getenv("MARIADB_DATABASE", "onlinejudge"),
    "charset": "utf8mb4",
    "cursorclass": DictCursor,
    "autocommit": True,
}


def hash_password(username: str, password: str) -> str:
    """Hash password with username appended after the password as requested."""
    return hashlib.sha256(f"{password}{username}".encode("utf-8")).hexdigest()


@contextmanager
def get_connection():
    connection = pymysql.connect(**DB_CONFIG)
    try:
        yield connection
    finally:
        connection.close()


def init_db(max_attempts: int = 20, delay_seconds: float = 1.5):
    last_error = None
    for _ in range(max_attempts):
        try:
            with get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(64) NOT NULL UNIQUE,
                            password_hash CHAR(64) NOT NULL,
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS login_events (
                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            ip_address VARCHAR(45) NOT NULL,
                            device_id CHAR(36) NOT NULL,
                            logged_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_login_events_user_time (user_id, logged_in_at),
                            INDEX idx_login_events_device_time (device_id, logged_in_at),
                            CONSTRAINT fk_login_events_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS login_security_alerts (
                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            first_ip_address VARCHAR(45) NOT NULL,
                            first_device_id CHAR(36) NOT NULL,
                            first_logged_in_at TIMESTAMP NOT NULL,
                            second_ip_address VARCHAR(45) NOT NULL,
                            second_device_id CHAR(36) NOT NULL,
                            second_logged_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_login_alerts_user_time (user_id, second_logged_in_at),
                            CONSTRAINT fk_login_alerts_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute(
                        """
                            CREATE TABLE IF NOT EXISTS submissions (
                                id INT AUTO_INCREMENT PRIMARY KEY,
                                user_id INT NOT NULL,
                                username VARCHAR(64) NOT NULL,
                                problem_id VARCHAR(32) NOT NULL,
                                language VARCHAR(16) NOT NULL,
                                status VARCHAR(16) NOT NULL,
                                result_json JSON NOT NULL,
                                submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                INDEX idx_submissions_user_time (user_id, submitted_at),
                                INDEX idx_submissions_username_time (username, submitted_at),
                                CONSTRAINT fk_submissions_user
                                    FOREIGN KEY (user_id) REFERENCES users(id)
                                    ON DELETE CASCADE
                            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                        """
                    )
            return
        except pymysql.MySQLError as exc:
            last_error = exc
            sleep(delay_seconds)
    raise RuntimeError(f"Could not initialize MariaDB tables: {last_error}")


def create_user(username: str, password: str):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, hash_password(username, password)),
            )
            return {"id": cursor.lastrowid, "username": username}


def authenticate_user(username: str, password: str):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,),
            )
            user = cursor.fetchone()
    if not user or user["password_hash"] != hash_password(username, password):
        return None
    return {"id": user["id"], "username": user["username"]}


def record_login(user_id: int, ip_address: str, device_id: str):
    """Store a login and return active alerts plus the newly created alert, if any."""
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id
                FROM login_events
                WHERE user_id = %s
                  AND device_id = %s
                  AND logged_in_at >= UTC_TIMESTAMP() - INTERVAL 3 HOUR
                LIMIT 1
                """,
                (user_id, device_id),
            )
            if cursor.fetchone():
                # A page reload signs in again with the same browser-local ID.
                # Do not create another event. Keep the alert visible only on
                # the later device that originally caused the alert.
                active_alerts = list_login_alerts(connection, user_id)
                current_device_alert = next(
                    (alert for alert in active_alerts if alert["second_device_id"] == device_id),
                    None,
                )
                return active_alerts, current_device_alert

            cursor.execute(
                """
                SELECT ip_address, device_id, logged_in_at
                FROM login_events
                WHERE user_id = %s
                  AND logged_in_at >= UTC_TIMESTAMP() - INTERVAL 3 HOUR
                  AND device_id <> %s
                ORDER BY logged_in_at DESC
                LIMIT 1
                """,
                (user_id, device_id),
            )
            previous_login = cursor.fetchone()
            new_alert = None
            cursor.execute(
                "INSERT INTO login_events (user_id, ip_address, device_id) VALUES (%s, %s, %s)",
                (user_id, ip_address, device_id),
            )
            if previous_login:
                new_alert = {
                    "first_ip_address": previous_login["ip_address"],
                    "first_device_id": previous_login["device_id"],
                    "second_ip_address": ip_address,
                    "second_device_id": device_id,
                }
                cursor.execute(
                    """
                    INSERT INTO login_security_alerts (
                        user_id, first_ip_address, first_device_id, first_logged_in_at,
                        second_ip_address, second_device_id
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        new_alert["first_ip_address"],
                        new_alert["first_device_id"],
                        previous_login["logged_in_at"],
                        new_alert["second_ip_address"],
                        new_alert["second_device_id"],
                    ),
                )
        return list_login_alerts(connection, user_id), new_alert


def list_login_alerts_for_user(user_id: int):
    with get_connection() as connection:
        return list_login_alerts(connection, user_id)


def is_submission_blocked(user_id: int, device_id: str) -> bool:
    """Only the device that triggered a recent cross-device alert is blocked."""
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1
                FROM login_security_alerts
                WHERE user_id = %s
                  AND second_device_id = %s
                  AND second_logged_in_at >= UTC_TIMESTAMP() - INTERVAL 3 HOUR
                LIMIT 1
                """,
                (user_id, device_id),
            )
            return cursor.fetchone() is not None


def find_recent_other_user_on_device(user_id: int, device_id: str):
    """Return another account that used this browser device in the last three hours."""
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT users.id, users.username, login_events.ip_address, login_events.logged_in_at
                FROM login_events
                JOIN users ON users.id = login_events.user_id
                WHERE login_events.device_id = %s
                  AND login_events.user_id <> %s
                  AND login_events.logged_in_at >= UTC_TIMESTAMP() - INTERVAL 3 HOUR
                ORDER BY login_events.logged_in_at DESC
                LIMIT 1
                """,
                (device_id, user_id),
            )
            return cursor.fetchone()


def list_login_alerts(connection, user_id: int):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, first_ip_address, first_device_id, first_logged_in_at,
                   second_ip_address, second_device_id, second_logged_in_at
            FROM login_security_alerts
            WHERE user_id = %s
              AND second_logged_in_at >= UTC_TIMESTAMP() - INTERVAL 3 HOUR
            ORDER BY second_logged_in_at DESC, id DESC
            """,
            (user_id,),
        )
        alerts = cursor.fetchall()
    for alert in alerts:
        for field in ("first_logged_in_at", "second_logged_in_at"):
            if isinstance(alert[field], datetime):
                alert[field] = alert[field].isoformat()
    return alerts


def save_submission(user_id: int, username: str, problem_id: str, language: str, result: dict):
    import json

    status = result.get("status", "UNKNOWN")
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO submissions (user_id, username, problem_id, language, status, result_json)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (user_id, username, problem_id, language, status, json.dumps(result, ensure_ascii=False)),
            )
            return cursor.lastrowid


def list_submissions(user_id: int):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                    SELECT id, username, problem_id, language, status, result_json, submitted_at
                    FROM submissions
                    WHERE user_id = %s
                    ORDER BY submitted_at DESC, id DESC
                    LIMIT 100
                """,
                (user_id,),
            )
            rows = cursor.fetchall()
    for row in rows:
        submitted_at = row.get("submitted_at")
        if isinstance(submitted_at, datetime):
            row["submitted_at"] = submitted_at.isoformat()
    return rows
