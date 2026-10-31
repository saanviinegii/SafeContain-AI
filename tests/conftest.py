import pytest
from backend.app.api.v1.router import platform_ctx
from backend.app.audit.ledger import ChainedAuditLedger

@pytest.fixture(autouse=True)
def isolate_test_ledger(tmp_path):
    """Ensures each pytest test runs with an isolated audit ledger to prevent concurrency issues."""
    test_storage = str(tmp_path / "test_audit_ledger.jsonl")
    platform_ctx.ledger = ChainedAuditLedger(test_storage)
    yield
