import importlib
import sys
from pathlib import Path

import pytest


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
database = importlib.import_module("database")

STRONG_PASSWORD = "x" * database.MIN_DB_PASSWORD_CHARS


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ("MARIADB_HOST", "MARIADB_PORT", "MARIADB_USER", "MARIADB_PASSWORD", "MARIADB_DATABASE"):
        monkeypatch.delenv(name, raising=False)


def test_missing_user_is_rejected(monkeypatch):
    monkeypatch.setenv("MARIADB_PASSWORD", STRONG_PASSWORD)
    with pytest.raises(RuntimeError, match="MARIADB_USER"):
        database.db_config()


@pytest.mark.parametrize("password", ["", "short", "onlinejudge"])
def test_missing_short_or_published_password_is_rejected(monkeypatch, password):
    monkeypatch.setenv("MARIADB_USER", "oj_app")
    monkeypatch.setenv("MARIADB_PASSWORD", password)
    with pytest.raises(RuntimeError, match="MARIADB_PASSWORD"):
        database.db_config()


def test_credentials_come_only_from_environment(monkeypatch):
    monkeypatch.setenv("MARIADB_USER", "oj_app")
    monkeypatch.setenv("MARIADB_PASSWORD", STRONG_PASSWORD)
    config = database.db_config()
    assert config["user"] == "oj_app"
    assert config["password"] == STRONG_PASSWORD
    assert config["host"] == "host.docker.internal"
    assert config["port"] == 3306


def test_connection_is_not_attempted_without_credentials(monkeypatch):
    def fail_connect(**_kwargs):
        raise AssertionError("must not connect without valid credentials")

    monkeypatch.setattr(database.pymysql, "connect", fail_connect)
    with pytest.raises(RuntimeError):
        with database.get_connection():
            pass
