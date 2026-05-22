from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import AccessEvent, Alert, HoneyToken, ThreatScore


def generate_snapshot_report(db: Session) -> Path:
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "honeytokens": db.query(HoneyToken).count(),
            "events": db.query(AccessEvent).count(),
            "alerts": db.query(Alert).count(),
            "scored_sources": db.query(ThreatScore).count(),
        },
        "top_threats": [
            {
                "source_ip": score.source_ip,
                "score": score.score,
                "level": score.level,
                "reasons": json.loads(score.reasons_json or "[]"),
            }
            for score in db.query(ThreatScore)
            .order_by(ThreatScore.score.desc(), ThreatScore.updated_at.desc())
            .limit(10)
            .all()
        ],
    }
    path = settings.report_dir / "ghosttrace-latest-report.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
