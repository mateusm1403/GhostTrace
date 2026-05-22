from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.entities import AccessEvent, HoneyToken
from app.services.honeytokens import mark_triggered


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: ("<redacted>" if key.lower() in {"authorization", "x-api-key"} else value)
        for key, value in headers.items()
    }


def record_request_event(
    db: Session,
    request: Request,
    response_code: int,
    honeytoken: HoneyToken | None = None,
) -> AccessEvent:
    event = AccessEvent(
        honeytoken_id=honeytoken.id if honeytoken else None,
        source_ip=client_ip(request),
        headers_json=json.dumps(safe_headers(dict(request.headers)), sort_keys=True),
        request_method=request.method,
        user_agent=request.headers.get("user-agent", "unknown"),
        path=request.url.path,
        query_params_json=json.dumps(dict(request.query_params), sort_keys=True),
        response_code=response_code,
    )
    if honeytoken:
        mark_triggered(db, honeytoken)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def record_synthetic_event(
    db: Session,
    *,
    source_ip: str,
    method: str,
    path: str,
    user_agent: str,
    response_code: int,
    headers: dict[str, str] | None = None,
    query_params: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> AccessEvent:
    event = AccessEvent(
        source_ip=source_ip,
        headers_json=json.dumps(headers or {"user-agent": user_agent}, sort_keys=True),
        request_method=method,
        user_agent=user_agent,
        path=path,
        query_params_json=json.dumps(query_params or {}, sort_keys=True),
        response_code=response_code,
    )
    if timestamp:
        event.timestamp = timestamp
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
