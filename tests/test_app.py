from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_dashboard_loads() -> None:
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "GhostTrace" in response.text


def test_simulation_generates_alerts() -> None:
    with TestClient(app) as client:
        response = client.get("/simulate/nikto")
        alerts = client.get("/api/alerts")
    assert response.status_code == 200
    assert response.json()["events_created"] > 0
    assert alerts.status_code == 200
