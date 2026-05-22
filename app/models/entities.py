from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TokenType(str, Enum):
    URL = "URL"
    CONFIG_FILE = "CONFIG_FILE"
    API_TOKEN = "API_TOKEN"


class TokenStatus(str, Enum):
    ACTIVE = "ACTIVE"
    TRIGGERED = "TRIGGERED"
    DISABLED = "DISABLED"


class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HoneyToken(Base):
    __tablename__ = "honeytokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    identifier: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(120))
    secret: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    location: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(32), default=TokenStatus.ACTIVE.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    events: Mapped[list["AccessEvent"]] = relationship(back_populates="honeytoken")


class AccessEvent(Base):
    __tablename__ = "access_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    honeytoken_id: Mapped[int | None] = mapped_column(ForeignKey("honeytokens.id"))
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    headers_json: Mapped[str] = mapped_column(Text)
    request_method: Mapped[str] = mapped_column(String(16), index=True)
    user_agent: Mapped[str] = mapped_column(String(500), index=True)
    path: Mapped[str] = mapped_column(String(1000), index=True)
    query_params_json: Mapped[str] = mapped_column(Text)
    response_code: Mapped[int] = mapped_column(Integer, index=True)

    honeytoken: Mapped[HoneyToken | None] = relationship(back_populates="events")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    level: Mapped[str] = mapped_column(String(32), index=True)
    score: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    reasons_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[str] = mapped_column(String(32), default=ThreatLevel.LOW.value, index=True)
    reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
