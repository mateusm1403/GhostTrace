from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.analyzers.threat_analyzer import analyze_events
from app.db.session import get_db
from app.models.entities import AccessEvent, Alert, HoneyToken, ThreatScore
from app.services.events import record_request_event
from app.services.honeytokens import (
    create_api_token,
    create_config_file_token,
    create_url_token,
)
from app.services.reports import generate_snapshot_report
from app.services.simulation import simulate_bruteforce, simulate_dirbuster, simulate_nikto

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        dashboard_context(db),
    )


@router.get("/dashboard/summary", response_class=HTMLResponse)
def dashboard_summary(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "partials/summary.html",
        dashboard_context(db),
    )


@router.post("/tokens/url")
def new_url_token(db: Session = Depends(get_db)) -> JSONResponse:
    token = create_url_token(db)
    return JSONResponse(_token_payload(token))


@router.post("/tokens/api")
def new_api_token(db: Session = Depends(get_db)) -> JSONResponse:
    token = create_api_token(db)
    return JSONResponse(_token_payload(token))


@router.post("/tokens/config")
def new_config_token(db: Session = Depends(get_db)) -> JSONResponse:
    token = create_config_file_token(db)
    return JSONResponse(_token_payload(token))


@router.get("/api/tokens")
def list_tokens(db: Session = Depends(get_db)) -> list[dict]:
    return [_token_payload(token) for token in db.query(HoneyToken).order_by(desc(HoneyToken.created_at)).all()]


@router.get("/api/events")
def list_events(db: Session = Depends(get_db)) -> list[dict]:
    events = db.query(AccessEvent).order_by(desc(AccessEvent.timestamp)).limit(100).all()
    return [_event_payload(event) for event in events]


@router.get("/api/alerts")
def list_alerts(db: Session = Depends(get_db)) -> list[dict]:
    alerts = db.query(Alert).order_by(desc(Alert.created_at)).limit(50).all()
    return [_alert_payload(alert) for alert in alerts]


@router.post("/analyze")
def run_analysis(db: Session = Depends(get_db)) -> JSONResponse:
    scores = analyze_events(db)
    return JSONResponse({"status": "ok", "sources_analyzed": len(scores)})


@router.get("/reports/latest")
def latest_report(db: Session = Depends(get_db)) -> JSONResponse:
    path = generate_snapshot_report(db)
    return JSONResponse(json.loads(Path(path).read_text(encoding="utf-8")))


@router.get("/simulate/nikto")
def route_simulate_nikto(db: Session = Depends(get_db)) -> JSONResponse:
    count = simulate_nikto(db)
    analyze_events(db)
    return JSONResponse({"simulation": "nikto", "events_created": count})


@router.get("/simulate/dirbuster")
def route_simulate_dirbuster(db: Session = Depends(get_db)) -> JSONResponse:
    count = simulate_dirbuster(db)
    analyze_events(db)
    return JSONResponse({"simulation": "dirbuster", "events_created": count})


@router.get("/simulate/bruteforce")
def route_simulate_bruteforce(db: Session = Depends(get_db)) -> JSONResponse:
    count = simulate_bruteforce(db)
    analyze_events(db)
    return JSONResponse({"simulation": "bruteforce", "events_created": count})


@router.api_route("/t/{identifier}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@router.api_route("/t/{identifier}/{extra_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def trigger_honeytoken(
    identifier: str,
    request: Request,
    extra_path: str = "",
    db: Session = Depends(get_db),
) -> PlainTextResponse:
    token = db.query(HoneyToken).filter(HoneyToken.identifier == identifier).first()
    status = 200 if token else 404
    record_request_event(db, request, status, token)
    if token:
        return PlainTextResponse("OK", status_code=200)
    return PlainTextResponse("Not Found", status_code=404)


@router.api_route("/{unknown_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def capture_unknown_path(
    unknown_path: str,
    request: Request,
    db: Session = Depends(get_db),
) -> PlainTextResponse:
    ignored_prefixes = ("static/", "favicon.ico")
    if unknown_path.startswith(ignored_prefixes):
        return PlainTextResponse("Not Found", status_code=404)
    record_request_event(db, request, 404)
    return PlainTextResponse("Not Found", status_code=404)


def dashboard_context(db: Session) -> dict:
    total_events = db.query(AccessEvent).count()
    total_tokens = db.query(HoneyToken).count()
    total_alerts = db.query(Alert).count()
    top_ips = (
        db.query(AccessEvent.source_ip, func.count(AccessEvent.id).label("count"))
        .group_by(AccessEvent.source_ip)
        .order_by(desc("count"))
        .limit(8)
        .all()
    )
    top_agents = (
        db.query(AccessEvent.user_agent, func.count(AccessEvent.id).label("count"))
        .group_by(AccessEvent.user_agent)
        .order_by(desc("count"))
        .limit(8)
        .all()
    )
    recent_events = db.query(AccessEvent).order_by(desc(AccessEvent.timestamp)).limit(12).all()
    recent_alerts = db.query(Alert).order_by(desc(Alert.created_at)).limit(8).all()
    threat_scores = db.query(ThreatScore).order_by(desc(ThreatScore.score)).limit(8).all()
    tokens = db.query(HoneyToken).order_by(desc(HoneyToken.created_at)).limit(8).all()
    timeline = (
        db.query(func.strftime("%H:%M", AccessEvent.timestamp), func.count(AccessEvent.id))
        .group_by(func.strftime("%H:%M", AccessEvent.timestamp))
        .order_by(func.strftime("%H:%M", AccessEvent.timestamp))
        .limit(24)
        .all()
    )
    return {
        "total_events": total_events,
        "total_tokens": total_tokens,
        "total_alerts": total_alerts,
        "top_ips": top_ips,
        "top_agents": top_agents,
        "recent_events": recent_events,
        "recent_alerts": recent_alerts,
        "threat_scores": threat_scores,
        "tokens": tokens,
        "timeline": timeline,
    }


def _token_payload(token: HoneyToken) -> dict:
    return {
        "id": token.id,
        "identifier": token.identifier,
        "type": token.token_type,
        "name": token.name,
        "secret": token.secret,
        "location": token.location,
        "status": token.status,
        "created_at": token.created_at.isoformat(),
        "last_triggered_at": token.last_triggered_at.isoformat() if token.last_triggered_at else None,
    }


def _event_payload(event: AccessEvent) -> dict:
    return {
        "id": event.id,
        "source_ip": event.source_ip,
        "timestamp": event.timestamp.isoformat(),
        "method": event.request_method,
        "user_agent": event.user_agent,
        "path": event.path,
        "query_params": json.loads(event.query_params_json or "{}"),
        "response_code": event.response_code,
        "honeytoken_id": event.honeytoken_id,
    }


def _alert_payload(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "level": alert.level,
        "score": alert.score,
        "title": alert.title,
        "reasons": json.loads(alert.reasons_json or "[]"),
        "created_at": alert.created_at.isoformat(),
    }
