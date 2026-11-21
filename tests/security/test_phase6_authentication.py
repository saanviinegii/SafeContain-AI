"""SafeContain AI Phase 6 Authentication & Authorization Test Suite.

Comprehensive end-to-end security verification covering 23 test cases:
1. Public endpoint accessibility (health probe)
2. 401 Unauthorized enforcement across unauthenticated calls
3. Bad credential rejection
4. Successful JWT token issuance and role assertion for ADMIN, ANALYST, VIEWER
5. JWT tampering, expiration, and header malformation rejection
6. Caller identity profile verification (/auth/me)
7. RBAC hierarchy enforcement across ADMIN, ANALYST, and VIEWER privilege tiers
8. Role self-assertion rejection in governance transitions
9. CSV ingestion protection (ADMIN only)
10. Full administrative user lifecycle (create, role update, deactivation, self-deactivation protection)
"""

from datetime import datetime, timedelta, timezone
import io
import uuid
import jwt
import pytest
from starlette.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app
from backend.app.security.roles import AppRole
from backend.app.security.user_store import user_store
from backend.app.security.auth import create_access_token


@pytest.fixture(scope="module")
def client():
    """Provides a thread-safe HTTP TestClient wired to the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def admin_token(client):
    """Logs in as admin and returns bearer token."""
    res = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "Admin@SafeContain2026!",
    })
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token(client):
    """Logs in as analyst and returns bearer token."""
    res = client.post("/api/v1/auth/login", json={
        "username": "analyst",
        "password": "Analyst@SafeContain2026!",
    })
    assert res.status_code == 200, f"Analyst login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def viewer_token(client):
    """Logs in as viewer and returns bearer token."""
    res = client.post("/api/v1/auth/login", json={
        "username": "viewer",
        "password": "Viewer@SafeContain2026!",
    })
    assert res.status_code == 200, f"Viewer login failed: {res.text}"
    return res.json()["access_token"]


# =====================================================================
# 1. PUBLIC & UNAUTHENTICATED ENDPOINT TESTS
# =====================================================================

def test_01_public_health_accessible_without_token(client):
    """Health probe MUST remain public, unauthenticated, and return 200 OK."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "graph_backend" in data
    assert "neo4j_connected" in data


def test_02_unauthenticated_requests_rejected(client):
    """Protected endpoints MUST return 401 Unauthorized when called without Authorization header."""
    protected_urls = [
        "/api/v1/auth/me",
        "/api/v1/metrics",
        "/api/v1/graph/topology",
        "/api/v1/graph/attack-paths",
        "/api/v1/graph/diagnostic",
        "/api/v1/audit/ledger",
    ]
    for url in protected_urls:
        res = client.get(url)
        assert res.status_code == 401, f"Expected 401 for unauthenticated {url}, got {res.status_code}"
        assert "detail" in res.json()


# =====================================================================
# 2. CREDENTIAL VALIDATION & LOGIN TESTS
# =====================================================================

def test_03_invalid_login_credentials_rejected(client):
    """Login with invalid username or password MUST return 401 Unauthorized."""
    # Unknown username
    res1 = client.post("/api/v1/auth/login", json={
        "username": "non_existent_user_999",
        "password": "SomePassword123!",
    })
    assert res1.status_code == 401
    assert "Invalid username or password" in res1.json()["detail"]

    # Wrong password
    res2 = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "WrongPassword123!",
    })
    assert res2.status_code == 401
    assert "Invalid username or password" in res2.json()["detail"]


def test_04_successful_admin_login(client):
    """Admin login returns 200, signed access_token, and ADMIN user profile."""
    res = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "Admin@SafeContain2026!",
    })
    assert res.status_code == 200
    body = res.json()
    assert "access_token" in body
    assert body["token_type"].lower() == "bearer"
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "ADMIN"
    assert body["user"]["is_active"] is True


def test_05_successful_analyst_login(client):
    """Analyst login returns 200, signed access_token, and ANALYST user profile."""
    res = client.post("/api/v1/auth/login", json={
        "username": "analyst",
        "password": "Analyst@SafeContain2026!",
    })
    assert res.status_code == 200
    body = res.json()
    assert "access_token" in body
    assert body["user"]["username"] == "analyst"
    assert body["user"]["role"] == "ANALYST"


def test_06_successful_viewer_login(client):
    """Viewer login returns 200, signed access_token, and VIEWER user profile."""
    res = client.post("/api/v1/auth/login", json={
        "username": "viewer",
        "password": "Viewer@SafeContain2026!",
    })
    assert res.status_code == 200
    body = res.json()
    assert "access_token" in body
    assert body["user"]["username"] == "viewer"
    assert body["user"]["role"] == "VIEWER"


# =====================================================================
# 3. JWT TOKEN TAMPERING, EXPIRY & FORMAT TESTS
# =====================================================================

def test_07_tampered_token_rejected(client, admin_token):
    """Tampering with token payload or signature MUST return 401 Unauthorized."""
    # Mutate the last 8 characters of signature
    tampered = admin_token[:-8] + "ABCDEFGH"
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered}"})
    assert res.status_code == 401
    assert "Invalid authentication token" in res.json()["detail"]


def test_08_expired_token_rejected(client):
    """Tokens with expiration timestamp in the past MUST return 401 Unauthorized."""
    expired_token = create_access_token(
        {"sub": "admin", "uid": "usr-admin-01", "role": "ADMIN"},
        expires_delta=timedelta(minutes=-30)
    )
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "Token has expired" in res.json()["detail"]


def test_09_malformed_auth_header_rejected(client):
    """Malformed Authorization headers MUST return 401 Unauthorized."""
    # Basic auth scheme instead of Bearer
    res1 = client.get("/api/v1/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert res1.status_code == 401

    # Empty Bearer
    res2 = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer "})
    assert res2.status_code == 401

    # Random string
    res3 = client.get("/api/v1/auth/me", headers={"Authorization": "RandomGarbageString"})
    assert res3.status_code == 401


# =====================================================================
# 4. PROFILE & RBAC ROLE RETRIEVAL TESTS
# =====================================================================

def test_10_auth_me_returns_caller_profile(client, admin_token, analyst_token, viewer_token):
    """Endpoint /auth/me returns the verified identity and role from the JWT."""
    res_admin = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    assert res_admin.json()["username"] == "admin"
    assert res_admin.json()["role"] == "ADMIN"

    res_analyst = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_analyst.status_code == 200
    assert res_analyst.json()["username"] == "analyst"
    assert res_analyst.json()["role"] == "ANALYST"

    res_viewer = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_viewer.status_code == 200
    assert res_viewer.json()["username"] == "viewer"
    assert res_viewer.json()["role"] == "VIEWER"


# =====================================================================
# 5. RBAC HIERARCHY & FORBIDDEN ACCESS TESTS (403 FORBIDDEN)
# =====================================================================

def test_11_admin_endpoints_accessible_by_admin(client, admin_token):
    """Administrator possesses sufficient privilege to invoke administrative endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    assert client.get("/api/v1/auth/users", headers=headers).status_code == 200
    assert client.get("/api/v1/graph/diagnostic", headers=headers).status_code == 200
    assert client.post("/api/v1/graph/neo4j/sync", headers=headers).status_code == 200


def test_12_admin_endpoints_forbidden_for_analyst(client, analyst_token):
    """Analyst attempting to invoke ADMIN endpoints MUST be rejected with 403 Forbidden."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    admin_endpoints = [
        ("GET", "/api/v1/auth/users"),
        ("GET", "/api/v1/graph/diagnostic"),
        ("POST", "/api/v1/graph/neo4j/sync"),
        ("POST", "/api/v1/dataset/import"),
        ("POST", "/api/v1/dataset/reset"),
    ]
    for method, path in admin_endpoints:
        if method == "GET":
            res = client.get(path, headers=headers)
        else:
            res = client.post(path, headers=headers)
        assert res.status_code == 403, f"Expected 403 for analyst on {path}, got {res.status_code}"
        assert "Insufficient privileges" in res.json()["detail"]


def test_13_admin_endpoints_forbidden_for_viewer(client, viewer_token):
    """Viewer attempting to invoke ADMIN endpoints MUST be rejected with 403 Forbidden."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    admin_endpoints = [
        ("GET", "/api/v1/auth/users"),
        ("GET", "/api/v1/graph/diagnostic"),
        ("POST", "/api/v1/dataset/reset"),
        ("POST", "/api/v1/graph/neo4j/sync"),
    ]
    for method, path in admin_endpoints:
        if method == "GET":
            res = client.get(path, headers=headers)
        else:
            res = client.post(path, headers=headers)
        assert res.status_code == 403, f"Expected 403 for viewer on {path}, got {res.status_code}"


def test_14_analyst_endpoints_accessible_by_analyst(client, analyst_token):
    """Analyst can invoke tactical threat analysis and planning endpoints."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    assert client.get("/api/v1/graph/attack-paths", headers=headers).status_code == 200
    assert client.get("/api/v1/evidence/sensitivity", headers=headers).status_code == 200
    assert client.get("/api/v1/planning/candidates", headers=headers).status_code == 200
    assert client.post("/api/v1/planning/optimize", json={"budget_limit": 10000.0}, headers=headers).status_code == 200
    assert client.post("/api/v1/simulation/run", json={}, headers=headers).status_code == 200


def test_15_analyst_endpoints_forbidden_for_viewer(client, viewer_token):
    """Viewer attempting to invoke ANALYST endpoints MUST be rejected with 403 Forbidden."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    analyst_endpoints = [
        ("GET", "/api/v1/graph/attack-paths"),
        ("GET", "/api/v1/evidence/sensitivity"),
        ("GET", "/api/v1/planning/candidates"),
        ("POST", "/api/v1/planning/optimize", {"budget_limit": 10000.0}),
        ("POST", "/api/v1/simulation/run", {}),
    ]
    for item in analyst_endpoints:
        method = item[0]
        path = item[1]
        payload = item[2] if len(item) > 2 else None
        if method == "GET":
            res = client.get(path, headers=headers)
        else:
            res = client.post(path, json=payload, headers=headers)
        assert res.status_code == 403, f"Expected 403 for viewer on {path}, got {res.status_code}"


def test_16_admin_can_access_analyst_and_viewer_endpoints(client, admin_token):
    """Role hierarchy guarantees ADMIN can access ANALYST and VIEWER endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    assert client.get("/api/v1/graph/attack-paths", headers=headers).status_code == 200
    assert client.get("/api/v1/graph/topology", headers=headers).status_code == 200
    assert client.get("/api/v1/metrics", headers=headers).status_code == 200


def test_17_viewer_endpoints_accessible_by_all_authenticated_roles(client, admin_token, analyst_token, viewer_token):
    """VIEWER tier endpoints are accessible by all authenticated callers."""
    for token in [admin_token, analyst_token, viewer_token]:
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/v1/graph/topology", headers=headers).status_code == 200
        assert client.get("/api/v1/metrics", headers=headers).status_code == 200
        assert client.get("/api/v1/dataset/status", headers=headers).status_code == 200
        assert client.get("/api/v1/audit/ledger", headers=headers).status_code == 200


# =====================================================================
# 6. CSV INGESTION RBAC ENFORCEMENT
# =====================================================================

def test_18_csv_upload_requires_admin(client, admin_token, analyst_token, viewer_token):
    """Multipart CSV ingestion endpoint /api/v1/ingestion/csv requires ADMIN role."""
    csv_bytes = b"node_id,name,node_type,criticality\nsrv-sec-test,Test Server,SERVER,0.85\n"

    # Viewer fails with 403
    res_viewer = client.post(
        "/api/v1/ingestion/csv",
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res_viewer.status_code == 403

    # Analyst fails with 403
    res_analyst = client.post(
        "/api/v1/ingestion/csv",
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert res_analyst.status_code == 403

    # Admin succeeds with 200
    res_admin = client.post(
        "/api/v1/ingestion/csv",
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["status"] == "SUCCESS"


# =====================================================================
# 7. ROLE SELF-ASSERTION PREVENTION (GOVERNANCE TRANSITIONS)
# =====================================================================

def test_19_role_self_assertion_prevention_in_governance(client, analyst_token, admin_token):
    """Client role self-assertion in request payloads is ignored; identity and role derive from JWT."""
    # Ensure a plan exists and is simulated
    client.post("/api/v1/simulation/run", json={}, headers={"Authorization": f"Bearer {analyst_token}"})

    # Transition to PENDING_APPROVAL
    res_pend = client.post("/api/v1/governance/transition", json={
        "target_status": "PENDING_APPROVAL",
        "actor_id": "attacker-analyst",
        "actor_role": "SOC_ANALYST",
        "notes": "Plan ready for approval",
    }, headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_pend.status_code == 200

    # Analyst attempts to self-assert "PLATFORM_ADMIN" in the request payload to force APPROVED
    malicious_payload = {
        "target_status": "APPROVED",
        "actor_id": "malicious-actor",
        "actor_role": "PLATFORM_ADMIN",  # Self-asserted privilege escalation attempt
        "notes": "Self-approved containment action",
    }
    res_exploit = client.post(
        "/api/v1/governance/transition",
        json=malicious_payload,
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    # The server ignores actor_role: PLATFORM_ADMIN in body, derives actor_role=SOC_ANALYST from token, and raises 403!
    assert res_exploit.status_code == 403
    assert "not authorized" in res_exploit.json()["detail"].lower()

    # Legitimately authorized approval with ADMIN token succeeds
    res_legit = client.post(
        "/api/v1/governance/transition",
        json={
            "target_status": "APPROVED",
            "actor_id": "admin",
            "actor_role": "SECURITY_ADMIN",
            "notes": "Authorized by platform administrator.",
        },
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_legit.status_code == 200
    assert res_legit.json()["status"] == "APPROVED"


# =====================================================================
# 8. USER MANAGEMENT & LIFECYCLE TESTS (SQLITE STORE)
# =====================================================================

TEST_USERNAME = f"contractor_{uuid.uuid4().hex[:6]}"
TEST_PASSWORD = "ContractorPassword2026!"


def test_20_user_management_provisions_new_account(client, admin_token):
    """Administrator can provision new users and newly created users can immediately log in."""
    new_user_data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
        "role": "ANALYST",
        "email": f"{TEST_USERNAME}@enterprise.gov",
        "full_name": "SOC Contractor Specialist",
    }
    # Create user as Admin
    res_create = client.post(
        "/api/v1/auth/users",
        json=new_user_data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_create.status_code == 200
    created = res_create.json()
    assert created["username"] == TEST_USERNAME
    assert created["role"] == "ANALYST"

    # Log in as the new user
    res_login = client.post("/api/v1/auth/login", json={
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
    })
    assert res_login.status_code == 200
    assert "access_token" in res_login.json()


def test_21_user_role_update_enforced(client, admin_token):
    """Updating a user's role updates their privilege boundary."""
    users = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_token}"}).json()
    target_user = next((u for u in users if u["username"] == TEST_USERNAME), None)
    assert target_user is not None

    # Update role to VIEWER
    res_update = client.put(
        f"/api/v1/auth/users/{target_user['id']}/role",
        json={"role": "VIEWER"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_update.status_code == 200
    assert res_update.json()["role"] == "VIEWER"

    # Contractor logs in again to receive new VIEWER token
    res_login = client.post("/api/v1/auth/login", json={
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
    })
    assert res_login.status_code == 200
    new_token = res_login.json()["access_token"]

    # Newly demoted user is now forbidden on ANALYST endpoints
    res_forbidden = client.get(
        "/api/v1/graph/attack-paths",
        headers={"Authorization": f"Bearer {new_token}"}
    )
    assert res_forbidden.status_code == 403


def test_22_deactivated_user_blocked_from_login(client, admin_token):
    """Deactivating an account immediately blocks future authentication attempts."""
    users = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_token}"}).json()
    target_user = next((u for u in users if u["username"] == TEST_USERNAME), None)
    assert target_user is not None

    # Deactivate account
    res_deact = client.patch(
        f"/api/v1/auth/users/{target_user['id']}/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_deact.status_code == 200
    assert res_deact.json()["is_active"] is False

    # Attempt login
    res_blocked = client.post("/api/v1/auth/login", json={
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
    })
    assert res_blocked.status_code == 401
    assert "account is deactivated" in res_blocked.json()["detail"].lower()


def test_23_admin_cannot_deactivate_own_account(client, admin_token):
    """Administrator cannot deactivate their own active account, preventing platform lockout."""
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"}).json()
    res = client.patch(
        f"/api/v1/auth/users/{me['id']}/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 400
    assert "cannot deactivate their own account" in res.json()["detail"].lower()
