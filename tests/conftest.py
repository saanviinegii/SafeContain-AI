import os
import pytest

# Ensure offline test execution does not attempt slow network/DNS retries against Neo4j Aura
os.environ["GRAPH_BACKEND"] = "in_memory"

@pytest.fixture(autouse=True)
def isolate_test_ledger(tmp_path):
    """Ensures each pytest test runs with an isolated audit ledger and in-memory graph to prevent network timeouts."""
    from backend.app.api.v1.router import platform_ctx
    from backend.app.audit.ledger import ChainedAuditLedger
    from backend.app.graph.engine import GraphEngine

    test_storage = str(tmp_path / "test_audit_ledger.jsonl")
    platform_ctx.ledger = ChainedAuditLedger(test_storage)
    if platform_ctx.engine is None or platform_ctx.engine.mode != "in_memory":
        platform_ctx.engine = GraphEngine(mode="in_memory")
    yield
