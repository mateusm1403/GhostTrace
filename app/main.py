from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.api.routes import router
from app.core.logging import configure_logging, logger
from app.core.scheduler import create_scheduler, run_analytics_job
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.services.events import record_request_event
from app.services.honeytokens import find_api_honeytoken


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    init_db()
    scheduler = create_scheduler()
    scheduler.start()
    logger.info("app.started")
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)
        logger.info("app.stopped")


app = FastAPI(
    title="GhostTrace",
    description="HoneyToken Manager and Intrusion Detection Analytics Platform",
    version="1.0.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.middleware("http")
async def api_token_capture_middleware(request: Request, call_next):
    response = await call_next(request)
    db: Session = SessionLocal()
    try:
        token = find_api_honeytoken(
            db,
            request.headers.get("authorization") or request.headers.get("x-api-key"),
        )
        if token:
            record_request_event(db, request, response.status_code, token)
            run_analytics_job()
    finally:
        db.close()
    return response


app.include_router(router)
