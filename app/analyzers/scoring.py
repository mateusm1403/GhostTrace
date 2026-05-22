from __future__ import annotations

from app.models.entities import ThreatLevel


SUSPICIOUS_USER_AGENTS = {
    "nikto": 35,
    "dirbuster": 30,
    "sqlmap": 35,
    "nmap": 25,
    "masscan": 25,
    "acunetix": 35,
    "nessus": 30,
}

SUSPICIOUS_PATH_FRAGMENTS = [
    "/.env",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/admin",
    "/cgi-bin",
    "/etc/passwd",
    "/.git",
    "/server-status",
    "/config",
    "/backup",
]


def level_for_score(score: int) -> ThreatLevel:
    if score >= 90:
        return ThreatLevel.CRITICAL
    if score >= 60:
        return ThreatLevel.HIGH
    if score >= 30:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW
