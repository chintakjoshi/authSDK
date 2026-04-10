"""Trusted-proxy-aware client IP extraction helpers."""

from __future__ import annotations

import ipaddress

from fastapi import Request

from app.config import get_settings
from app.service_registry import service_cached


def normalize_ip(ip_address: str | None) -> str | None:
    """Normalize IP strings to canonical form and drop malformed values."""
    if not ip_address:
        return None
    try:
        return str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        return None


@service_cached
def get_trusted_proxy_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    """Parse configured trusted proxy CIDRs once per settings load."""
    networks: list[ipaddress._BaseNetwork] = []
    for raw_cidr in get_settings().app.trusted_proxy_cidrs:
        try:
            networks.append(ipaddress.ip_network(raw_cidr.strip(), strict=False))
        except ValueError:
            continue
    return tuple(networks)


def is_trusted_proxy(ip_address: str | None) -> bool:
    """Return True when the peer IP is an explicitly trusted proxy."""
    normalized = normalize_ip(ip_address)
    if normalized is None:
        return False
    parsed_ip = ipaddress.ip_address(normalized)
    return any(parsed_ip in network for network in get_trusted_proxy_networks())


def extract_client_ip(request: Request) -> str | None:
    """Extract the originating client IP, honoring XFF only from trusted proxies."""
    client = request.client
    peer_ip = normalize_ip(client.host if client is not None else None)
    if peer_ip is None:
        return None

    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if not forwarded_for or not is_trusted_proxy(peer_ip):
        return peer_ip

    forwarded_chain = [normalize_ip(item) for item in forwarded_for.split(",")]
    forwarded_ips = [item for item in forwarded_chain if item is not None]
    if not forwarded_ips:
        return peer_ip

    # Walk from the edge proxy inward and return the first hop that is not another trusted proxy.
    for candidate in reversed(forwarded_ips):
        if not is_trusted_proxy(candidate):
            return candidate
    return forwarded_ips[0]
