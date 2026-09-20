import sys
from pathlib import Path
from types import SimpleNamespace

import dns.exception
import dns.name
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_names


@pytest.fixture(autouse=True)
def no_name_overrides(monkeypatch):
    monkeypatch.delenv("DEVICE_NAME_MAP", raising=False)


def test_admin_name_takes_precedence_without_dns(monkeypatch):
    monkeypatch.setenv("DEVICE_NAME_MAP", '{"192.168.137.1":"ganges-desktop"}')
    def unexpected(*args, **kwargs):
        pytest.fail("override must not query DNS")
    monkeypatch.setattr(device_names.dns.resolver, "resolve_address", unexpected)
    assert device_names.resolve_device_name("192.168.137.1") == "ganges-desktop"


def test_reverse_dns_is_bounded_and_normalized(monkeypatch):
    def lookup(address, *, lifetime):
        assert address == "192.168.137.1"
        assert lifetime == 0.5
        return [SimpleNamespace(target=dns.name.from_text("ganges-desktop.lan."))]
    monkeypatch.setattr(device_names.dns.resolver, "resolve_address", lookup)
    assert device_names.resolve_device_name("192.168.137.1") == "ganges-desktop.lan"


def test_unavailable_dns_leaves_name_empty(monkeypatch):
    def timeout(*args, **kwargs):
        raise dns.exception.Timeout
    monkeypatch.setattr(device_names.dns.resolver, "resolve_address", timeout)
    assert device_names.resolve_device_name("192.168.137.1") == ""


def test_invalid_address_does_not_query_dns(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid address must not query DNS")
    monkeypatch.setattr(device_names.dns.resolver, "resolve_address", unexpected)
    assert device_names.resolve_device_name("unknown") == ""


@pytest.mark.parametrize("value", ['[]', '{"bad-ip":"name"}', '{"127.0.0.1":"bad\\nname"}'])
def test_invalid_configuration_fails_clearly(monkeypatch, value):
    monkeypatch.setenv("DEVICE_NAME_MAP", value)
    with pytest.raises(ValueError, match="DEVICE_NAME_MAP"):
        device_names.configured_device_names()
