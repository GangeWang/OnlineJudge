import hashlib
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
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_until TIMESTAMP NULL")
                    cursor.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) NOT NULL DEFAULT ''")
                    cursor.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP NULL")
                    cursor.execute("ALTER TABLE login_events ADD COLUMN IF NOT EXISTS outcome VARCHAR(32) NOT NULL DEFAULT 'accepted'")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_events_ip_time ON login_events (ip_address, logged_in_at)")
                    for column, definition in (
                        ("ip_address", "VARCHAR(45) NULL"),
                        ("device_id", "CHAR(36) NULL"),
                        ("session_hash", "CHAR(64) NULL"),
                        ("browser_fingerprint", "CHAR(64) NULL"),
                    ):
                        cursor.execute(f"ALTER TABLE submissions ADD COLUMN IF NOT EXISTS {column} {definition}")
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS security_events (
                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            reason VARCHAR(32) NOT NULL,
                            ip_address VARCHAR(45) NOT NULL,
                            device_id CHAR(36) NOT NULL,
                            browser_fingerprint CHAR(64) NOT NULL,
                            session_hash CHAR(64) NULL,
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_security_user_time (user_id, created_at)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS submission_audit (
                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NULL,
                            session_hash CHAR(64) NULL,
                            ip_address VARCHAR(45) NOT NULL,
                            device_id CHAR(36) NOT NULL,
                            browser_fingerprint CHAR(64) NOT NULL,
                            problem_id VARCHAR(32) NOT NULL,
                            outcome VARCHAR(32) NOT NULL,
                            submission_id INT NULL,
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_audit_user_time (user_id, created_at)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """)
                    # Preserve active restrictions from pre-upgrade alerts, for all sessions.
                    cursor.execute("""
                        UPDATE users u JOIN (
                            SELECT user_id, MAX(second_logged_in_at) + INTERVAL 3 HOUR AS until_at
                            FROM login_security_alerts GROUP BY user_id
                        ) a ON a.user_id = u.id
                        SET u.blocked_until = GREATEST(COALESCE(u.blocked_until, a.until_at), a.until_at)
                        WHERE a.until_at > CURRENT_TIMESTAMP()
                    """)
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


def save_submission(connection, user_id: int, username: str, problem_id: str, language: str, result: dict, source_code: str, provenance: dict):
    import json

    status = result.get("status", "UNKNOWN")
    source_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest()
    normalized = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]", source_code)
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
                source_code, source_hash, ip_address, device_id, session_hash, browser_fingerprint
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id, username, problem_id, language, status,
                json.dumps(result, ensure_ascii=False), source_code, source_hash,
                provenance["ip_address"], provenance["device_id"],
                provenance["session_hash"], provenance["browser_fingerprint"],
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
