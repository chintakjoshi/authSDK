"""Minimal user-agent parsing for admin session display."""

from __future__ import annotations

_BROWSERS: tuple[tuple[str, str], ...] = (
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("Opera", "Opera"),
    ("Chrome/", "Chrome"),
    ("Firefox/", "Firefox"),
    ("Safari/", "Safari"),
)

_OPERATING_SYSTEMS: tuple[tuple[str, str], ...] = (
    ("Windows", "Windows"),
    ("Android", "Android"),
    ("iPhone", "iOS"),
    ("iPad", "iOS"),
    ("Mac OS X", "macOS"),
    ("Macintosh", "macOS"),
    ("Linux", "Linux"),
    ("CrOS", "ChromeOS"),
)


def parse_device_label(user_agent: str | None) -> str:
    """Return a short human-readable device label like "Chrome on Windows"."""
    if not user_agent:
        return "Unknown"
    browser = _match(user_agent, _BROWSERS)
    operating_system = _match(user_agent, _OPERATING_SYSTEMS)
    if browser and operating_system:
        return f"{browser} on {operating_system}"
    if browser:
        return browser
    if operating_system:
        return operating_system
    return "Unknown"


def _match(user_agent: str, table: tuple[tuple[str, str], ...]) -> str | None:
    """Return the first label whose token appears in the user agent string."""
    for token, label in table:
        if token in user_agent:
            return label
    return None
