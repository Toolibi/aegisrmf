from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("AEGIS_DATABASE_URL", "sqlite:///./aegis.db"))
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("AEGIS_DATA_DIR", "./data")))
    # Server-side pepper for API-key hashing and HMAC key for signed manifests.
    # In Azure these come from Key Vault via managed identity; never commit real values.
    key_pepper: str = field(default_factory=lambda: os.getenv("AEGIS_KEY_PEPPER", "dev-only-pepper-change-me"))
    manifest_signing_key: str = field(default_factory=lambda: os.getenv("AEGIS_MANIFEST_KEY", "dev-only-manifest-key"))
    bootstrap_token: str | None = field(default_factory=lambda: os.getenv("AEGIS_BOOTSTRAP_TOKEN"))
    max_upload_bytes: int = int(os.getenv("AEGIS_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
    # AI provider: "rules" (local, deterministic, no data leaves the boundary) or "azure-foundry".
    ai_provider: str = field(default_factory=lambda: os.getenv("AEGIS_AI_PROVIDER", "rules"))
    # Azure AI deployment facts used by the three-part CUI gate (evidence/cui_gate.py).
    ai_model: str = field(default_factory=lambda: os.getenv("AEGIS_AI_MODEL", ""))
    ai_region: str = field(default_factory=lambda: os.getenv("AEGIS_AI_REGION", ""))
    ai_deployment_type: str = field(default_factory=lambda: os.getenv("AEGIS_AI_DEPLOYMENT_TYPE", ""))
    ai_data_zone: str = field(default_factory=lambda: os.getenv("AEGIS_AI_DATA_ZONE", ""))
    ai_fedramp_high_confirmed: bool = field(default_factory=lambda: os.getenv("AEGIS_AI_FEDRAMP_HIGH_CONFIRMED", "false").lower() == "true")
    ai_dfars_confirmed_by: str = field(default_factory=lambda: os.getenv("AEGIS_AI_DFARS_CONFIRMED_BY", ""))
    ai_dfars_confirmed_on: str = field(default_factory=lambda: os.getenv("AEGIS_AI_DFARS_CONFIRMED_ON", ""))

    def ai_deployment(self):
        from .evidence.cui_gate import AIDeployment
        return AIDeployment(self.ai_model, self.ai_region, self.ai_deployment_type, self.ai_data_zone,
                            self.ai_fedramp_high_confirmed, self.ai_dfars_confirmed_by, self.ai_dfars_confirmed_on)
    environment: str = field(default_factory=lambda: os.getenv("AEGIS_ENV", "dev"))

    def validate_for_production(self) -> list[str]:
        problems = []
        if self.environment == "prod":
            if "dev-only" in self.key_pepper or "dev-only" in self.manifest_signing_key:
                problems.append("dev secrets in production")
            if self.database_url.startswith("sqlite"):
                problems.append("sqlite is not supported in production; use PostgreSQL")
        return problems


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def set_settings(s: Settings) -> None:
    global _settings
    _settings = s
