import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal
from backend.models import Organization, User, Incident, MessagingPolicy, MessagingIdentity

client = TestClient(app)

AUTH_HEADER = {"Authorization": "Bearer aegis_jwt_token_usr-soc-01"}
ADMIN_HEADER = {"Authorization": "Bearer aegis_jwt_token_usr-admin-01"}

@pytest.fixture(scope="module", autouse=True)
def setup_cross_tenant_fixture():
    db = SessionLocal()
    # Ensure competitor organization exists
    comp_org = db.query(Organization).filter(Organization.organization_id == "org-competitor-bank").first()
    if not comp_org:
        comp_org = Organization(
            organization_id="org-competitor-bank",
            name="Competitor Financial",
            industry="Banking",
            country="Singapore"
        )
        db.add(comp_org)
        db.commit()

    comp_user = db.query(User).filter(User.user_id == "usr-competitor-01").first()
    if not comp_user:
        comp_user = User(
            user_id="usr-competitor-01",
            organization_id="org-competitor-bank",
            email="threat.analyst@competitor.test",
            password_hash="sha256_mock_hash",
            role="SOC Lead",
            status="ACTIVE"
        )
        db.add(comp_user)
        db.commit()

    db.close()
    yield

def test_cross_tenant_isolation_blocked():
    """Security Test: Cross-tenant recipient discovery and conversation must be strictly blocked"""
    # 1. Directory search must not disclose competitor user
    res = client.get("/api/v1/messaging/recipients?q=threat.analyst", headers=AUTH_HEADER)
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 0
    assert not any(i["user_id"] == "usr-competitor-01" for i in items)

    # 2. Direct authorization attempt must fail with 403
    auth_res = client.post(
        "/api/v1/messaging/rooms/authorize",
        headers=AUTH_HEADER,
        json={"recipient_user_id": "usr-competitor-01"}
    )
    assert auth_res.status_code == 403
    assert "Cross-tenant messaging is prohibited" in auth_res.json()["detail"]

def test_suspended_user_authorization_rejected():
    """Security Test: Offboarding hook - suspended users cannot send or receive authorized messages"""
    # 1. Admin suspends analyst
    suspend_res = client.post("/api/v1/messaging/users/usr-admin-01/suspend", headers=ADMIN_HEADER)
    assert suspend_res.status_code == 200
    assert suspend_res.json()["status"] == "SUSPENDED"

    # 2. Requester tries to authorize chat with suspended user
    try:
        chat_res = client.post(
            "/api/v1/messaging/rooms/authorize",
            headers=AUTH_HEADER,
            json={"recipient_user_id": "usr-admin-01"}
        )
        assert chat_res.status_code == 403
        assert "inactive or suspended" in chat_res.json()["detail"]
    finally:
        # Reactivate user for subsequent tests
        react_res = client.post("/api/v1/messaging/users/usr-admin-01/reactivate", headers=ADMIN_HEADER)
        assert react_res.status_code == 200
        assert react_res.json()["status"] == "ACTIVE"

    # Verify authorization works again after reactivation
    react_auth = client.post(
        "/api/v1/messaging/rooms/authorize",
        headers=AUTH_HEADER,
        json={"recipient_user_id": "usr-admin-01"}
    )
    assert react_auth.status_code == 200
    assert react_auth.json()["allowed"] is True

def test_policy_messaging_disabled():
    """Security Test: Disabling organizational policy immediately revokes authorization"""
    # 1. Disable messaging in policy
    put_res = client.put("/api/v1/messaging/policy", headers=ADMIN_HEADER, json={"messaging_enabled": False})
    assert put_res.status_code == 200

    try:
        # Directory search should now fail
        rec_res = client.get("/api/v1/messaging/recipients", headers=AUTH_HEADER)
        assert rec_res.status_code == 403

        # Room authorization should fail
        auth_res = client.post(
            "/api/v1/messaging/rooms/authorize",
            headers=AUTH_HEADER,
            json={"recipient_user_id": "usr-admin-01"}
        )
        assert auth_res.status_code == 403
    finally:
        # Restore policy
        client.put("/api/v1/messaging/policy", headers=ADMIN_HEADER, json={"messaging_enabled": True})

def test_unauthorized_incident_link_blocked():
    """Security Test: Users cannot link a room to an incident they do not own or that doesn't exist"""
    res = client.post(
        "/api/v1/messaging/rooms/link",
        headers=AUTH_HEADER,
        json={
            "matrix_room_id": "!foreign_room:chat.aegis-x.internal",
            "room_type": "INCIDENT",
            "incident_id": "non-existent-inc-id-999"
        }
    )
    assert res.status_code == 404
