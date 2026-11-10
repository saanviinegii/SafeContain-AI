"""SafeContain AI Configuration & Environment Settings.

Provides centralized, validated configuration for graph connections, database,
risk thresholds, solver parameters, security policies, and audit retention.
"""

from typing import Any, List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """System-wide configuration settings with environment override support."""
    
    # Platform Metadata
    PROJECT_NAME: str = "SafeContain AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    PORT: int = Field(default=8000, description="Server port, automatically populated by Render/Cloud platforms")
    ENVIRONMENT: str = Field(default="development", description="development | testing | staging | production")
    DEBUG: bool = False
    
    # Graph Engine Configuration
    GRAPH_BACKEND: str = Field(
        default="dual",
        description="dual | neo4j | in_memory. Dual tries Neo4j then seamlessly falls back to In-Memory NetworkX engine."
    )
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    NEO4J_DATABASE: str = "neo4j"
    NEO4J_MAX_CONNECTION_LIFETIME: int = 3600
    NEO4J_MAX_CONNECTION_POOL_SIZE: int = 50
    NEO4J_CONNECTION_TIMEOUT: float = 3.0  # Seconds before fallback in dual mode
    
    # Relational Database / PostgreSQL
    DATABASE_URL: Optional[str] = "postgresql://postgres:postgres@localhost:5432/safecontain"
    USE_SQLITE_FALLBACK: bool = True  # For embedded offline / zero-setup testing
    SQLITE_DB_PATH: str = "safecontain_app.db"
    
    # Audit & Security
    SECRET_KEY: str = "safecontain-enterprise-dev-secret-key-change-in-production-min32bytes"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    ALGORITHM: str = "HS256"
    AUDIT_LEDGER_STORAGE_PATH: str = "audit_ledger.jsonl"
    VERIFY_AUDIT_INTEGRITY_ON_STARTUP: bool = True
    
    # Optimization & Solvers
    OPTIMIZATION_DEFAULT_STRATEGY: str = "constraint_cpsat"
    MAX_SOLVER_TIME_SECONDS: float = 10.0
    DEFAULT_MAX_CONTAINMENT_BUDGET: float = 50000.0
    MAX_ALLOWABLE_WORKFLOW_OUTAGE_HOURS: float = 0.0  # Zero outage for Tier-1 critical citizen/payment services
    
    # Uncertainty & Evidence Scoring
    EVIDENCE_STALENESS_THRESHOLD_HOURS: float = 72.0
    UNCERTAINTY_PENALTY_WEIGHT: float = 0.35  # Penalty added to risk when path relies on suspected/unverified nodes
    CONFIDENCE_DECAY_RATE_PER_DAY: float = 0.05
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost",
        "http://127.0.0.1",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            clean_str = v.strip()
            if clean_str.startswith("["):
                import json
                try:
                    return json.loads(clean_str)
                except Exception:
                    pass
            return [origin.strip() for origin in clean_str.split(",") if origin.strip()]
        elif isinstance(v, (list, tuple)):
            return list(v)
        return []

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
