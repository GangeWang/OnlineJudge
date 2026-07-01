import hashlib
import os
from contextlib import contextmanager
from datetime import datetime
from time import sleep

import pymysql
from pymysql.cursors import DictCursor

DB_CONFIG = {
    "host": os.getenv("MARIADB_HOST", "mariadb"),
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
                        CREATE TABLE IF NOT EXISTS submissions (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            problem_id VARCHAR(32) NOT NULL,
                            language VARCHAR(16) NOT NULL,
                            status VARCHAR(16) NOT NULL,
                            result_json JSON NOT NULL,
                            submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_submissions_user_time (user_id, submitted_at),
                            CONSTRAINT fk_submissions_user
                                FOREIGN KEY (user_id) REFERENCES users(id)
                                ON DELETE CASCADE
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
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


def save_submission(user_id: int, problem_id: str, language: str, result: dict):
    import json

    status = result.get("status", "UNKNOWN")
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO submissions (user_id, problem_id, language, status, result_json)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, problem_id, language, status, json.dumps(result, ensure_ascii=False)),
            )
            return cursor.lastrowid


def list_submissions(user_id: int):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, problem_id, language, status, result_json, submitted_at
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
