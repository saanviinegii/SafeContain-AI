"""SafeContain AI Production Observability, Metrics, and Structured Telemetry.

Exposes system telemetry, execution latencies, solver runtimes, and health probes.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict
from pydantic import BaseModel, Field


class SystemMetrics(BaseModel):
    """Real-time platform metrics and operational health."""
    uptime_seconds: float
    total_ingested_events: int = 0
    active_graph_nodes: int = 0
    active_graph_edges: int = 0
    discovered_attack_paths: int = 0
    total_simulations_run: int = 0
    audit_chain_length: int = 0
    last_audit_verification_valid: bool = True
    cpsat_last_runtime_ms: float = 0.0
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MetricsCollector:
    """Singleton operational metrics tracker."""

    _start_time: float = time.time()
    _total_ingested: int = 0
    _total_simulations: int = 0
    _last_cpsat_ms: float = 0.0

    @classmethod
    def record_ingestion(cls, count: int) -> None:
        cls._total_ingested += count

    @classmethod
    def record_simulation(cls) -> None:
        cls._total_simulations += 1

    @classmethod
    def record_cpsat_time(cls, ms: float) -> None:
        cls._last_cpsat_ms = ms

    @classmethod
    def get_metrics(cls, engine, ledger) -> SystemMetrics:
        audit_rep = ledger.verify_integrity()
        return SystemMetrics(
            uptime_seconds=round(time.time() - cls._start_time, 2),
            total_ingested_events=cls._total_ingested,
            active_graph_nodes=len(engine.get_all_nodes()),
            active_graph_edges=len(engine.get_all_edges()),
            discovered_attack_paths=len(engine.find_attack_paths()),
            total_simulations_run=cls._total_simulations,
            audit_chain_length=len(ledger._events),
            last_audit_verification_valid=audit_rep.is_valid,
            cpsat_last_runtime_ms=cls._last_cpsat_ms,
        )
