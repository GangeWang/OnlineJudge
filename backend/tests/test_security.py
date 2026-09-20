import importlib
import os
import sys
from pathlib import Path

import pytest
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
