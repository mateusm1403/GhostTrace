from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from app.analyzers.threat_analyzer import analyze_events
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal


def run_analytics_job() -> None:
    db = SessionLocal()
    try:
        analyze_events(db)
    except Exception as exc:  # pragma: no cover - scheduler guardrail
        logger.error("analytics.failed", error=str(exc))
    finally:
        db.close()


def create_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        run_analytics_job,
        "interval",
        seconds=settings.analytics_interval_seconds,
        id="ghosttrace-threat-analytics",
        replace_existing=True,
    )
    return scheduler
