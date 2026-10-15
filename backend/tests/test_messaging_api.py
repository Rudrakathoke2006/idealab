import uuid
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal
from backend.models import User, Incident, MessagingPolicy, MessagingIdentity

client = TestClient(app)

AUTH_HEADER = {"Authorization": "Bearer aegis_jwt_token_usr-soc-01"}
ADMIN_HEADER = {"Authorization": "Bearer aegis_jwt_token_usr-admin-01"}

def test_bootstrap_unauthenticated():
    """Endpoint A: Reject unauthenticated requests with 401"""
    res = client.get("/api/v1/messaging/bootstrap")
    assert res.status_code == 401
    assert "detail" in res.json()

def test_bootstrap_authenticated():
    """Endpoint A: Returns client messaging configuration and Matrix user ID without secrets"""
    res = client.get("/api/v1/messaging/bootstrap", headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()
    assert data["enabled"] is True
    assert "chat.aegis-x.internal" in data["homeserver_url"]
    assert data["matrix_user_id"] == "@analyst_soc_01:chat.aegis-x.internal"
    assert data["encryption_required"] is True
    assert data["require_device_verification"] is True
    assert "policy_version" in data

    # Security check: Zero secrets leaked in bootstrap
    forbidden = ["password", "private_key", "secret", "recovery_secret", "admin_token"]
    for key in forbidden:
        assert key not in data

def test_recipients_directory_tenant_isolation():
    """Endpoint B: Search authorized recipients within the same tenant"""
    res = client.get("/api/v1/messaging/recipients", headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert isinstance(data["items"], list)
    
    # Requester should not appear in their own recipient list
    user_ids = [item["user_id"] for item in data["items"]]
    assert "usr-soc-01" not in user_ids
    assert "usr-admin-01" in user_ids

    # Query filter test
    res_filtered = client.get("/api/v1/messaging/recipients?q=admin", headers=AUTH_HEADER)
    assert res_filtered.status_code == 200
    filtered_ids = [item["user_id"] for item in res_filtered.json()["items"]]
    assert "usr-admin-01" in filtered_ids

def test_room_authorization_success():
    """Endpoint C: Authorize a direct conversation between tenant analysts"""
    res = client.post(
        "/api/v1/messaging/rooms/authorize",
        headers=AUTH_HEADER,
        json={"recipient_user_id": "usr-admin-01"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is True
    assert data["recipient_matrix_user_id"] == "@admin_01:chat.aegis-x.internal"
    assert data["recipient_user_id"] == "usr-admin-01"
    assert data["encryption_required"] is True
    assert data["require_device_verification"] is True

def test_room_authorization_invalid_recipient():
    """Endpoint C: Return 404 for nonexistent recipient"""
    res = client.post(
        "/api/v1/messaging/rooms/authorize",
        headers=AUTH_HEADER,
        json={"recipient_user_id": "non-existent-user-uuid"}
    )
    assert res.status_code == 404

def test_room_link_and_retrieval():
    """Endpoints D & E: Link room to incident and retrieve metadata"""
    db = SessionLocal()
    target_inc_id = f"inc-test-api-link-{uuid.uuid4().hex[:8]}"
    inc = Incident(
        incident_id=target_inc_id,
        organization_id="org-acme-fintech-01",
        title="Suspicious E2EE Incident",
        severity="HIGH",
        status="OPEN"
    )
    db.add(inc)
    db.commit()
    db.close()

    test_matrix_room = f"!test_room_{uuid.uuid4().hex[:8]}:chat.aegis-x.internal"

    # Link room
    link_res = client.post(
        "/api/v1/messaging/rooms/link",
        headers=AUTH_HEADER,
        json={
            "matrix_room_id": test_matrix_room,
            "room_type": "INCIDENT",
            "incident_id": target_inc_id
        }
    )
    assert link_res.status_code == 200
    link_data = link_res.json()
    assert link_data["status"] == "LINKED"
    assert link_data["matrix_room_id"] == test_matrix_room
    assert link_data["incident_id"] == target_inc_id

    # Retrieve via /messaging/incidents/{incident_id}/room
    get_res = client.get(f"/api/v1/messaging/incidents/{target_inc_id}/room", headers=AUTH_HEADER)
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["matrix_room_id"] == test_matrix_room
    assert get_data["encryption_required"] is True

    # Retrieve via direct alias /incidents/{incident_id}/messaging-room
    alias_res = client.get(f"/api/v1/incidents/{target_inc_id}/messaging-room", headers=AUTH_HEADER)
    assert alias_res.status_code == 200
    assert alias_res.json()["matrix_room_id"] == test_matrix_room

def test_privacy_security_events_audit():
    """Audit Endpoint: Ensure security events record metadata only, without plaintext or keys"""
    res = client.get("/api/v1/messaging/security-events", headers=AUTH_HEADER)
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)
    assert len(events) > 0

    for ev in events:
        assert "event_type" in ev
        assert "request_id" in ev
        # Details must never have plaintext or passwords
        details = ev.get("details") or {}
        for forbidden in ["plaintext", "message", "body", "password", "private_key", "secret"]:
            assert forbidden not in details
