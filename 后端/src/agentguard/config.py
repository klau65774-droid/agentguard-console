"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = "AgentGuard"
    app_env: str = "development"
    app_debug: bool = True
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_log_level: str = "INFO"

    # Auth
    api_key_header: str = "X-API-Key"
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"

    # Tenant
    default_tenant_id: str = "default"
    tenant_header: str = "X-Tenant-ID"

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_backend: str = "memory"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Database
    database_url: str = "postgresql://agentguard:agentguard@localhost:5432/agentguard"

    # Model providers
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    default_model_provider: str = "openai"
    default_model_name: str = "gpt-4o"

    # Policy
    policy_dir: str = str(_REPO_ROOT / "policies")
    default_policy: str = "default"

    # Prompt packages
    prompt_packages_dir: str = str(_REPO_ROOT / "prompt_packages")

    # Guardrails toggles
    input_guardrails_enabled: bool = True
    output_validation_enabled: bool = True
    action_governance_enabled: bool = True

    # Slop score
    slop_score_threshold_pass: float = 0.3
    slop_score_threshold_repair: float = 0.7

    # Observability
    enable_audit_log: bool = True
    enable_request_tracing: bool = True
    enable_quality_risk_metrics: bool = False
    enable_guardrail_timing_logs: bool = False
    expose_guardrail_latency_header: bool = True
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


settings = Settings()
