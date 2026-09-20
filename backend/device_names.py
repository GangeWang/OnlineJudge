"""Best-effort display names; never used as an authentication/device identity."""
import ipaddress
import json
import os
import re

import dns.exception
import dns.resolver

DNS_LOOKUP_SECONDS = 0.5


def _normalize_name(value: str) -> str:
    if not isinstance(value, str):
        return ""
    value = value.rstrip(".")
    return value if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", value) else ""


def configured_device_names() -> dict[str, str]:
    try:
        configured = json.loads(os.getenv("DEVICE_NAME_MAP", "") or "{}")
        if not isinstance(configured, dict):
            raise ValueError("expected an IP-to-hostname JSON object")
        result = {}
        for address, name in configured.items():
            address = str(ipaddress.ip_address(address))
            normalized = _normalize_name(name)
            if not normalized:
                raise ValueError("invalid hostname")
            result[address] = normalized
        return result
    except (TypeError, ValueError) as exc:
        raise ValueError("DEVICE_NAME_MAP must map valid IP addresses to hostnames") from exc


def resolve_device_name(address: str) -> str:
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        return ""
    configured = configured_device_names()
    if address in configured:
        return configured[address]
    try:
        answers = dns.resolver.resolve_address(address, lifetime=DNS_LOOKUP_SECONDS)
        for answer in answers:
            name = _normalize_name(answer.target.to_text())
            if name:
                return name
    except (dns.exception.DNSException, OSError):
        pass
    return ""
