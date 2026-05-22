from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pandas as pd
from sqlalchemy.orm import Session

from app.analyzers.scoring import (
    SUSPICIOUS_PATH_FRAGMENTS,
    SUSPICIOUS_USER_AGENTS,
    level_for_score,
)
from app.core.logging import logger
from app.models.entities import AccessEvent, Alert, ThreatLevel, ThreatScore, utc_now
from app.services.alerts import emit_alert


def _events_frame(db: Session, since: datetime) -> pd.DataFrame:
    events = (
        db.query(AccessEvent)
        .filter(AccessEvent.timestamp >= since)
        .order_by(AccessEvent.timestamp.asc())
        .all()
    )
    return pd.DataFrame(
        [
            {
                "source_ip": event.source_ip,
                "timestamp": event.timestamp,
                "method": event.request_method,
                "user_agent": event.user_agent or "",
                "path": event.path or "",
                "response_code": event.response_code,
                "honeytoken_id": event.honeytoken_id,
            }
            for event in events
        ]
    )


def analyze_events(db: Session, lookback_minutes: int = 60) -> list[ThreatScore]:
    since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    frame = _events_frame(db, since)
    if frame.empty:
        logger.info("analytics.no_events", lookback_minutes=lookback_minutes)
        return []

    updated_scores: list[ThreatScore] = []
    for source_ip, group in frame.groupby("source_ip"):
        score, reasons = score_group(group)
        level = level_for_score(score)
        existing = db.query(ThreatScore).filter(ThreatScore.source_ip == source_ip).first()
        if not existing:
            existing = ThreatScore(source_ip=source_ip)
        existing.score = score
        existing.level = level.value
        existing.reasons_json = json.dumps(reasons)
        existing.event_count = int(len(group))
        existing.updated_at = utc_now()
        db.add(existing)
        db.flush()
        updated_scores.append(existing)
        if level in {ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL}:
            _create_alert_if_needed(db, source_ip, level.value, score, reasons)

    db.commit()
    logger.info("analytics.completed", sources=len(updated_scores))
    return updated_scores


def score_group(group: pd.DataFrame) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    user_agents = " ".join(group["user_agent"].fillna("").str.lower().tolist())
    paths = group["path"].fillna("").str.lower()
    methods = group["method"].fillna("").str.upper()

    for signature, weight in SUSPICIOUS_USER_AGENTS.items():
        if signature in user_agents:
            score += weight
            reasons.append(f"{signature.title()} scanner signature observed (+{weight})")

    repeated_404 = int((group["response_code"] == 404).sum())
    if repeated_404 >= 10:
        score += 20
        reasons.append(f"Repeated 404 responses: {repeated_404} hits (+20)")

    head_options = int(methods.isin(["HEAD", "OPTIONS"]).sum())
    if head_options >= 8:
        score += 15
        reasons.append(f"HEAD/OPTIONS probing: {head_options} requests (+15)")

    event_count = len(group)
    if event_count >= 30:
        score += 25
        reasons.append(f"High-frequency requests in analysis window: {event_count} (+25)")

    suspicious_path_hits = int(paths.apply(_is_suspicious_path).sum())
    if suspicious_path_hits >= 5:
        score += 20
        reasons.append(f"Suspicious path enumeration: {suspicious_path_hits} paths (+20)")

    login_hits = int(paths.str.contains("login|signin|auth", regex=True).sum())
    if login_hits >= 10:
        score += 30
        reasons.append(f"Brute-force pattern against auth paths: {login_hits} attempts (+30)")

    honeytoken_hits = int(group["honeytoken_id"].notna().sum())
    if honeytoken_hits >= 1:
        weight = 20 if honeytoken_hits < 3 else 35
        score += weight
        reasons.append(f"Honeytoken access detected: {honeytoken_hits} hit(s) (+{weight})")

    unique_paths = int(paths.nunique())
    if unique_paths >= 20:
        score += 20
        reasons.append(f"Directory fuzzing pattern: {unique_paths} unique paths (+20)")

    if not reasons:
        reasons.append("Low-volume access without strong scanner indicators")

    return min(score, 100), reasons


def _is_suspicious_path(path: str) -> bool:
    return any(fragment in path for fragment in SUSPICIOUS_PATH_FRAGMENTS)


def _create_alert_if_needed(
    db: Session,
    source_ip: str,
    level: str,
    score: int,
    reasons: list[str],
) -> None:
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    duplicate = (
        db.query(Alert)
        .filter(Alert.source_ip == source_ip, Alert.level == level, Alert.created_at >= since)
        .first()
    )
    if duplicate:
        return
    alert = Alert(
        source_ip=source_ip,
        level=level,
        score=score,
        title=f"{level} threat activity from {source_ip}",
        reasons_json=json.dumps(reasons),
    )
    db.add(alert)
    db.flush()
    emit_alert(alert, reasons)
