from __future__ import annotations

import secrets
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import HoneyToken, TokenStatus, TokenType, utc_now


def _identifier() -> str:
    return secrets.token_hex(8)


def create_url_token(db: Session, name: str = "Decoy endpoint") -> HoneyToken:
    identifier = _identifier()
    token = HoneyToken(
        identifier=identifier,
        token_type=TokenType.URL.value,
        name=name,
        secret=f"gt-url-{identifier}",
        location=f"/t/{identifier}",
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def create_api_token(db: Session, name: str = "Leaked API key") -> HoneyToken:
    identifier = _identifier()
    secret = f"gt_live_{secrets.token_urlsafe(24)}"
    token = HoneyToken(
        identifier=identifier,
        token_type=TokenType.API_TOKEN.value,
        name=name,
        secret=secret,
        location="Authorization: Bearer <token> or X-API-Key",
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def create_config_file_token(db: Session, name: str = "Fake production config") -> HoneyToken:
    identifier = _identifier()
    api_secret = f"gt_conf_{secrets.token_urlsafe(22)}"
    filename = f"ghosttrace-prod-{identifier}.env"
    path = settings.honeypot_dir / filename
    callback_path = f"/t/{identifier}/config-check"
    content = "\n".join(
        [
            "# GhostTrace generated honeytoken configuration",
            "APP_ENV=production",
            "DB_HOST=prod-db.internal",
            "DB_USER=svc_backup",
            f"API_TOKEN={api_secret}",
            f"HEALTHCHECK_URL=http://127.0.0.1:{settings.app_port}{callback_path}",
            "",
        ]
    )
    path.write_text(content, encoding="utf-8")
    token = HoneyToken(
        identifier=identifier,
        token_type=TokenType.CONFIG_FILE.value,
        name=name,
        secret=api_secret,
        location=str(Path(path)),
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def find_api_honeytoken(db: Session, possible_secret: str | None) -> HoneyToken | None:
    if not possible_secret:
        return None
    secret = possible_secret.removeprefix("Bearer ").strip()
    return (
        db.query(HoneyToken)
        .filter(
            HoneyToken.token_type == TokenType.API_TOKEN.value,
            HoneyToken.secret == secret,
            HoneyToken.status != TokenStatus.DISABLED.value,
        )
        .first()
    )


def mark_triggered(db: Session, token: HoneyToken) -> None:
    token.status = TokenStatus.TRIGGERED.value
    token.last_triggered_at = utc_now()
    db.add(token)
