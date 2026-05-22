from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "GhostTrace"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    debug: bool = False
    database_url: str = "sqlite:///./ghosttrace.db"
    analytics_interval_seconds: int = 30
    report_dir: Path = Path("reports")
    honeypot_dir: Path = Path("honeypots")
    discord_webhook_url: str | None = None
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    def ensure_directories(self) -> None:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.honeypot_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
