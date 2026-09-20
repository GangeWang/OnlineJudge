import hashlib
import secrets
import os
import re
from difflib import SequenceMatcher
from contextlib import contextmanager
from datetime import datetime
from time import sleep

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
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


PASSWORD_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
                            password_hash VARCHAR(255) NOT NULL,
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS sessions (
                            token_hash CHAR(64) PRIMARY KEY,
                            user_id INT NOT NULL,
                            device_id CHAR(36) NOT NULL,
                            browser_fingerprint CHAR(64) NOT NULL DEFAULT '',
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            expires_at TIMESTAMP NOT NULL,
                            INDEX idx_sessions_user (user_id),
                            INDEX idx_sessions_expiry (expires_at),
                            CONSTRAINT fk_sessions_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS browser_fingerprint CHAR(64) NOT NULL DEFAULT ''")
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS submission_attempts (
                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            problem_id VARCHAR(32) NOT NULL,
                            attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_attempts_user_problem_time (user_id, problem_id, attempted_at),
                            INDEX idx_attempts_user_time (user_id, attempted_at),
                            CONSTRAINT fk_attempts_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
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
                            device_name VARCHAR(253) NOT NULL DEFAULT '',
                            browser_fingerprint CHAR(64) NOT NULL DEFAULT '',
                            logged_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_login_events_user_time (user_id, logged_in_at),
                            INDEX idx_login_events_device_time (device_id, logged_in_at),
                            INDEX idx_login_events_fingerprint_time (browser_fingerprint, logged_in_at),
                            CONSTRAINT fk_login_events_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute("ALTER TABLE login_events ADD COLUMN IF NOT EXISTS device_name VARCHAR(253) NOT NULL DEFAULT '' AFTER device_id")
                    cursor.execute("ALTER TABLE login_events ADD COLUMN IF NOT EXISTS browser_fingerprint CHAR(64) NOT NULL DEFAULT ''")
                    cursor.execute("ALTER TABLE users MODIFY password_hash VARCHAR(255) NOT NULL")
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS login_security_alerts (
                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            first_ip_address VARCHAR(45) NOT NULL,
                            first_device_id CHAR(36) NOT NULL,
                            first_browser_fp CHAR(64) NOT NULL DEFAULT '',
                            first_logged_in_at TIMESTAMP NOT NULL,
                            second_ip_address VARCHAR(45) NOT NULL,
                            second_device_id CHAR(36) NOT NULL,
                            second_browser_fp CHAR(64) NOT NULL DEFAULT '',
                            second_logged_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_login_alerts_user_time (user_id, second_logged_in_at),
                            INDEX idx_login_alerts_second_fp (user_id, second_browser_fp, second_logged_in_at),
                            CONSTRAINT fk_login_alerts_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                        """
                    )
                    cursor.execute("ALTER TABLE login_security_alerts ADD COLUMN IF NOT EXISTS first_browser_fp CHAR(64) NOT NULL DEFAULT ''")
                    cursor.execute("ALTER TABLE login_security_alerts ADD COLUMN IF NOT EXISTS second_browser_fp CHAR(64) NOT NULL DEFAULT ''")
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
                                source_code MEDIUMTEXT NOT NULL,
                                source_hash CHAR(64) NOT NULL,
                                submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                INDEX idx_submissions_user_time (user_id, submitted_at),
                                INDEX idx_submissions_username_time (username, submitted_at),
                                CONSTRAINT fk_submissions_user
                                    FOREIGN KEY (user_id) REFERENCES users(id)
                                    ON DELETE CASCADE
                            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                        """
                    )
                    cursor.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS source_code MEDIUMTEXT NULL")
                    cursor.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS source_hash CHAR(64) NULL")
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
                (username, hash_password(password)),
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
    if not user:
        return None
    stored_hash = user["password_hash"]
    try:
        valid = stored_hash.startswith("$argon2") and PASSWORD_HASHER.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError):
        valid = False
    if not valid and len(stored_hash) == 64:
        # Migrate accounts created with the legacy unsalted SHA-256 scheme.
        valid = stored_hash == hashlib.sha256(f"{password}{username}".encode("utf-8")).hexdigest()
        if valid:
            with get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET password_hash = %s WHERE id = %s",
                        (hash_password(password), user["id"]),
                    )
    if not valid:
        return None
    return {"id": user["id"], "username": user["username"]}


def create_session(user_id: int, device_id: str, browser_fingerprint: str = "", lifetime_hours: int = 12):
    token = secrets.token_urlsafe(32)
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO sessions (token_hash, user_id, device_id, browser_fingerprint, expires_at)
                VALUES (%s, %s, %s, %s, DATE_ADD(CURRENT_TIMESTAMP(), INTERVAL %s HOUR))
                """,
                (hash_session_token(token), user_id, device_id, browser_fingerprint, lifetime_hours),
            )
    return token


def get_session(token: str):
    if not token:
        return None
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT sessions.user_id, sessions.device_id,
                       sessions.browser_fingerprint, users.username
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = %s
                  AND sessions.expires_at > CURRENT_TIMESTAMP()
                """,
                (hash_session_token(token),),
            )
            return cursor.fetchone()


def record_submission_attempt(user_id: int, problem_id: str):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    TIMESTAMPDIFF(
                        SECOND,
                        MAX(CASE WHEN problem_id = %s THEN attempted_at END),
                        CURRENT_TIMESTAMP()
                    ) AS problem_elapsed,
                    TIMESTAMPDIFF(SECOND, MAX(attempted_at), CURRENT_TIMESTAMP()) AS global_elapsed
                FROM submission_attempts
                WHERE user_id = %s
                  AND attempted_at >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
                """,
                (problem_id, user_id),
            )
            latest = cursor.fetchone()
            problem_elapsed = latest["problem_elapsed"]
            global_elapsed = latest["global_elapsed"]
            if problem_elapsed is not None and problem_elapsed < 30:
                return 30 - max(problem_elapsed, 0)
            if global_elapsed is not None and global_elapsed < 2:
                return 2 - max(global_elapsed, 0)
            cursor.execute(
                "INSERT INTO submission_attempts (user_id, problem_id) VALUES (%s, %s)",
                (user_id, problem_id),
            )
            return 0


def record_login(user_id: int, ip_address: str, device_id: str, browser_fingerprint: str = "", device_name: str = ""):
    """Store a login and return active alerts plus the newly created alert, if any."""
    with get_connection() as connection:
        with connection.cursor() as cursor:
            if ip_address and browser_fingerprint:
                cursor.execute(
                    """
                    SELECT id
                    FROM login_events
                    WHERE user_id = %s
                      AND (
                          device_id = %s
                          OR (ip_address = %s AND browser_fingerprint = %s AND browser_fingerprint <> '')
                      )
                      AND logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                    LIMIT 1
                    """,
                    (user_id, device_id, ip_address, browser_fingerprint),
                )
            else:
                cursor.execute(
                    """
                    SELECT id
                    FROM login_events
                    WHERE user_id = %s
                      AND device_id = %s
                      AND logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                    LIMIT 1
                    """,
                    (user_id, device_id),
                )
            recent_login = cursor.fetchone()
            if recent_login:
                # Only enrich an unnamed event from the same IP/device; preserve history.
                if device_name:
                    cursor.execute(
                        "UPDATE login_events SET device_name = %s "
                        "WHERE id = %s AND device_id = %s AND ip_address = %s AND device_name = ''",
                        (device_name, recent_login["id"], device_id, ip_address),
                    )
                # A page reload or re-login from the same browser/device signs in again.
                # Do not create another event. Keep the alert visible only on
                # the later device that originally caused the alert.
                active_alerts = list_login_alerts(connection, user_id)
                current_device_alert = next(
                    (
                        alert for alert in active_alerts
                        if alert["second_device_id"] == device_id
                        or (browser_fingerprint and alert.get("second_browser_fp") == browser_fingerprint)
                    ),
                    None,
                )
                return active_alerts, current_device_alert

            if ip_address and browser_fingerprint:
                cursor.execute(
                    """
                    SELECT ip_address, device_id, browser_fingerprint, logged_in_at
                    FROM login_events
                    WHERE user_id = %s
                      AND logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                      AND device_id <> %s
                      AND (ip_address <> %s OR browser_fingerprint <> %s)
                    ORDER BY logged_in_at DESC
                    LIMIT 1
                    """,
                    (user_id, device_id, ip_address, browser_fingerprint),
                )
            else:
                cursor.execute(
                    """
                    SELECT ip_address, device_id, browser_fingerprint, logged_in_at
                    FROM login_events
                    WHERE user_id = %s
                      AND logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                      AND device_id <> %s
                    ORDER BY logged_in_at DESC
                    LIMIT 1
                    """,
                    (user_id, device_id),
                )
            previous_login = cursor.fetchone()
            new_alert = None
            cursor.execute(
                """
                INSERT INTO login_events (user_id, ip_address, device_id, browser_fingerprint, device_name)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, ip_address, device_id, browser_fingerprint, device_name),
            )
            if previous_login:
                new_alert = {
                    "first_ip_address": previous_login["ip_address"],
                    "first_device_id": previous_login["device_id"],
                    "first_browser_fp": previous_login.get("browser_fingerprint", ""),
                    "second_ip_address": ip_address,
                    "second_device_id": device_id,
                    "second_browser_fp": browser_fingerprint,
                }
                cursor.execute(
                    """
                    INSERT INTO login_security_alerts (
                        user_id, first_ip_address, first_device_id, first_browser_fp, first_logged_in_at,
                        second_ip_address, second_device_id, second_browser_fp
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        new_alert["first_ip_address"],
                        new_alert["first_device_id"],
                        new_alert["first_browser_fp"],
                        previous_login["logged_in_at"],
                        new_alert["second_ip_address"],
                        new_alert["second_device_id"],
                        new_alert["second_browser_fp"],
                    ),
                )
        return list_login_alerts(connection, user_id), new_alert


def list_login_alerts_for_user(user_id: int):
    with get_connection() as connection:
        return list_login_alerts(connection, user_id)


def is_submission_blocked(user_id: int, device_id: str, ip_address: str = "", browser_fingerprint: str = "") -> bool:
    """Block submissions on the later-login device while a cross-device alert is active."""
    with get_connection() as connection:
        with connection.cursor() as cursor:
            if ip_address and browser_fingerprint:
                cursor.execute(
                    """
                    SELECT 1
                    FROM login_security_alerts
                    WHERE user_id = %s
                      AND (
                          second_device_id = %s
                          OR (second_ip_address = %s AND second_browser_fp = %s AND second_browser_fp <> '')
                      )
                      AND second_logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                    LIMIT 1
                    """,
                    (user_id, device_id, ip_address, browser_fingerprint),
                )
            else:
                cursor.execute(
                    """
                    SELECT 1
                    FROM login_security_alerts
                    WHERE user_id = %s
                      AND second_device_id = %s
                      AND second_logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                    LIMIT 1
                    """,
                    (user_id, device_id),
                )
            return cursor.fetchone() is not None


def find_recent_other_user_on_device(user_id: int, device_id: str, ip_address: str = "", browser_fingerprint: str = ""):
    """Return another account that used this browser/device in the last three hours."""
    with get_connection() as connection:
        with connection.cursor() as cursor:
            if ip_address and browser_fingerprint:
                cursor.execute(
                    """
                    SELECT users.id, users.username, login_events.ip_address, login_events.logged_in_at
                    FROM login_events
                    JOIN users ON users.id = login_events.user_id
                    WHERE (
                        login_events.device_id = %s
                        OR (login_events.ip_address = %s AND login_events.browser_fingerprint = %s AND login_events.browser_fingerprint <> '')
                    )
                      AND login_events.user_id <> %s
                      AND login_events.logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                    ORDER BY login_events.logged_in_at DESC
                    LIMIT 1
                    """,
                    (device_id, ip_address, browser_fingerprint, user_id),
                )
            else:
                cursor.execute(
                    """
                    SELECT users.id, users.username, login_events.ip_address, login_events.logged_in_at
                    FROM login_events
                    JOIN users ON users.id = login_events.user_id
                    WHERE login_events.device_id = %s
                      AND login_events.user_id <> %s
                      AND login_events.logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
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
            SELECT id, first_ip_address, first_device_id, first_browser_fp, first_logged_in_at,
                   second_ip_address, second_device_id, second_browser_fp, second_logged_in_at
            FROM login_security_alerts
            WHERE user_id = %s
              AND second_logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
            ORDER BY second_logged_in_at DESC, id DESC
            """,
            (user_id,),
        )
        alerts = cursor.fetchall()
    for alert in alerts:
        for field in ("first_logged_in_at", "second_logged_in_at"):
            if isinstance(alert.get(field), datetime):
                alert[field] = alert[field].isoformat()
    return alerts


def save_submission(user_id: int, username: str, problem_id: str, language: str, result: dict, source_code: str):
    import json

    status = result.get("status", "UNKNOWN")
    source_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest()
    normalized = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]", source_code)
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT source_code
                FROM submissions
                WHERE problem_id = %s AND source_hash = %s AND source_code IS NOT NULL
                LIMIT 1
                """,
                (problem_id, source_hash),
            )
            exact_match = cursor.fetchone()
            if exact_match:
                result = dict(result)
                result["similarity_warning"] = "此程式與既有提交完全相同"
            else:
                cursor.execute(
                    "SELECT source_code FROM submissions WHERE problem_id = %s AND source_code IS NOT NULL ORDER BY id DESC LIMIT 100",
                    (problem_id,),
                )
                for row in cursor.fetchall():
                    other = re.findall(
                        r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]",
                        row["source_code"],
                    )
                    if SequenceMatcher(None, normalized, other).ratio() >= 0.9:
                        result = dict(result)
                        result["similarity_warning"] = "此程式與既有提交高度相似"
                        break
            cursor.execute(
                """
                INSERT INTO submissions (
                    user_id, username, problem_id, language, status, result_json,
                    source_code, source_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id, username, problem_id, language, status,
                    json.dumps(result, ensure_ascii=False), source_code, source_hash,
                ),
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
