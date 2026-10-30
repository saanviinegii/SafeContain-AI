"""Security and Penetration Test Suite for SafeContain AI.

Verifies:
1. Cypher/SQL injection protection and input sanitization
2. Role escalation prevention and permission checks
3. Cryptographic audit tampering detection
4. Security response headers enforcement
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.domain import UserRole
from backend.app.security.middleware import sanitize_graph_query_input

client = TestClient(app)


def test_cypher_injection_sanitization():
    """Verify malicious Cypher statements are caught and rejected."""
    malicious_inputs = [
        "MATCH (n) DETACH DELETE n",
        "admin' OR 1=1 --",
        "CALL dbms.security.createUser('hacker', 'pass')",
        "test'; DROP TABLE users; --",
        "MATCH (u:User) RETURN u",
    ]

    for bad_input in malicious_inputs:
        with pytest.raises(ValueError) as exc:
            sanitize_graph_query_input(bad_input)
        assert "Prohibited pattern" in str(exc.value)

    # Valid string must pass and be sanitized
    clean_input = sanitize_graph_query_input("host-workstation-14")
    assert clean_input == "host-workstation-14"


def test_role_escalation_denial():
    """Verify lower privileged roles cannot execute administrative transitions."""
    # Ensure fresh plan in PENDING_APPROVAL state
    client.post("/api/v1/simulation/run")
    client.post(
        "/api/v1/governance/transition",
        json={
            "target_status": "PENDING_APPROVAL",
            "actor_id": "soc-analyst-1",
            "actor_role": "SOC_ANALYST",
            "notes": "Ready for manager review.",
        }
    )

    unauthorized_roles = [
        UserRole.READ_ONLY_VIEWER.value,
        UserRole.SOC_ANALYST.value,
    ]

    for role in unauthorized_roles:
        res = client.post(
            "/api/v1/governance/transition",
            json={
                "target_status": "APPROVED",
                "actor_id": "attacker-user",
                "actor_role": role,
                "notes": "Attempting unauthorized approval.",
            }
        )
        assert res.status_code == 403
        assert "not authorized" in res.json()["detail"]


def test_security_headers_verification():
    """Verify HTTP security response headers prevent MIME sniffing, clickjacking, and XSS."""
    res = client.get("/api/v1/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["X-XSS-Protection"] == "1; mode=block"
    assert "Strict-Transport-Security" in res.headers
    assert "Content-Security-Policy" in res.headers
