from __future__ import annotations

from app.core.config import settings
from app.db.session import Base, engine
from app.models import entities  # noqa: F401 - imported so SQLAlchemy sees models


def init_db() -> None:
    settings.ensure_directories()
    Base.metadata.create_all(bind=engine)
