from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.services.events import record_synthetic_event


def simulate_nikto(db: Session) -> int:
    source_ip = "198.51.100.23"
    paths = [
        "/cgi-bin/test.cgi",
        "/server-status",
        "/icons/README",
        "/phpmyadmin/",
        "/admin/",
        "/.env",
        "/config.php",
        "/backup.zip",
        "/wp-admin/",
        "/index.php?option=com_users",
        "/t/unknown-nikto-probe",
        "/etc/passwd",
    ]
    return _emit_paths(db, source_ip, "Nikto/2.5.0", paths, methods=["GET", "HEAD"])


def simulate_dirbuster(db: Session) -> int:
    source_ip = "203.0.113.77"
    paths = [
        "/admin",
        "/administrator",
        "/backup",
        "/backups",
        "/db",
        "/old",
        "/uploads",
        "/private",
        "/portal",
        "/dev",
        "/test",
        "/tmp",
        "/assets",
        "/api",
        "/.git/config",
        "/config",
        "/config.old",
        "/wp-login.php",
        "/phpmyadmin",
        "/server-status",
        "/hidden",
        "/logs",
    ]
    return _emit_paths(db, source_ip, "DirBuster-1.0-RC1", paths, methods=["GET", "OPTIONS"])


def simulate_bruteforce(db: Session) -> int:
    source_ip = "192.0.2.44"
    count = 36
    now = datetime.now(timezone.utc)
    for index in range(count):
        record_synthetic_event(
            db,
            source_ip=source_ip,
            method="POST",
            path="/admin/login",
            user_agent="Mozilla/5.0 credential-checker",
            response_code=401 if index < count - 1 else 403,
            headers={"content-type": "application/x-www-form-urlencoded"},
            query_params={"username": f"admin{index % 4}"},
            timestamp=now - timedelta(seconds=count - index),
        )
    return count


def _emit_paths(
    db: Session,
    source_ip: str,
    user_agent: str,
    paths: list[str],
    methods: list[str],
) -> int:
    now = datetime.now(timezone.utc)
    count = 0
    for index, path in enumerate(paths):
        method = methods[index % len(methods)]
        response_code = 404 if path not in {"/api", "/assets"} else 200
        record_synthetic_event(
            db,
            source_ip=source_ip,
            method=method,
            path=path,
            user_agent=user_agent,
            response_code=response_code,
            timestamp=now - timedelta(seconds=len(paths) - index),
        )
        count += 1
    return count
