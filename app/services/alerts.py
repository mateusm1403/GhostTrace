from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app.core.config import settings
from app.core.logging import logger
from app.models.entities import Alert


def emit_alert(alert: Alert, reasons: list[str]) -> None:
    payload = {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "level": alert.level,
        "score": alert.score,
        "title": alert.title,
        "reasons": reasons,
        "created_at": alert.created_at.isoformat(),
    }
    logger.warning("alert.generated", **payload)
    write_json_report(payload)
    if settings.discord_webhook_url:
        send_discord_alert(payload)


def write_json_report(payload: dict) -> Path:
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = settings.report_dir / f"alert-{stamp}-{payload['source_ip'].replace(':', '_')}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def send_discord_alert(payload: dict) -> None:
    if not settings.discord_webhook_url:
        return
    try:
        httpx.post(
            settings.discord_webhook_url,
            json={
                "content": (
                    f"GhostTrace {payload['level']} alert: {payload['source_ip']} "
                    f"scored {payload['score']}"
                )
            },
            timeout=5,
        )
    except httpx.HTTPError as exc:
        logger.error("alert.discord_failed", error=str(exc))
