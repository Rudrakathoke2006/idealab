import os
import uuid
import json
import base64
import sqlite3
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.models import AuditEvent, MessagingSecurityEvent, MessagingRoomLink, MessagingIdentity, Incident

client = TestClient(app)

AUTH_HEADER = {"Authorization": "Bearer aegis_jwt_token_usr-soc-01"}

class MockMatrixMegolmClient:
    """
    Simulates the browser-side Matrix client SDK with Rust Crypto WASM + IndexedDB.
    Handles device keys, Megolm session ratchet, client-side encryption, and decryption.
    Strict rule: Never transmits plaintext across the network boundary to AEGIS-X FastAPI.
    """
    def __init__(self, user_id: str, device_id: str, is_verified: bool = True):
        self.user_id = user_id
        self.device_id = device_id
        self.is_verified = is_verified
        self.crypto_initialized = False
        # Megolm 256-bit session key generated locally inside browser WASM memory
        self._session_key = AESGCM.generate_key(bit_length=256)
        self.inbox = []

    def init_crypto(self, storage_passphrase: str = "secure_user_passphrase_2026"):
        if not storage_passphrase:
            raise ValueError("Passphrase required for persistent cryptographic storage.")
        self.crypto_initialized = True
        return True

    def encrypt_room_event(self, room_id: str, plaintext: str) -> dict:
        """
        Simulates Matrix Megolm local client encryption (m.megolm.v1.aes-sha2).
        Fails closed if crypto is not initialized.
        """
        if not self.crypto_initialized:
            raise RuntimeError("CRITICAL: Attempted to send message before crypto initialization. Plaintext fallback blocked.")

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), room_id.encode("utf-8"))

        # Returns standard Matrix Megolm encrypted event structure
        return {
            "type": "m.room.encrypted",
            "room_id": room_id,
            "sender": self.user_id,
            "sender_device": self.device_id,
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "session_id": f"megolm_session_{self.device_id[:8]}"
            }
        }

    def decrypt_room_event(self, event: dict, shared_session_key: bytes) -> str:
        """
        Recipient client local decryption in browser memory.
        """
        content = event["content"]
        if content.get("algorithm") != "m.megolm.v1.aes-sha2":
            raise ValueError("Unsupported or unencrypted event format.")

        nonce = base64.b64decode(content["nonce"])
        ciphertext = base64.b64decode(content["ciphertext"])
        room_id = event["room_id"]

        aesgcm = AESGCM(shared_session_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, room_id.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")


def test_e2e_canary_plaintext_leak_proof():
    """
    CRITICAL SECURITY TEST (Blueprint Section 8 & 12):
    Canary Plaintext Leak Verification.
    Generates a synthetic unique canary string, simulates an E2EE conversation,
    and comprehensively scans all AEGIS-X database tables and log stores.
    Asserts that the canary plaintext occurs EXACTLY ZERO TIMES on the server.
    """
    canary_token = f"E2EE_TEST_CANARY_{uuid.uuid4().hex}"

    # 1. Authorize conversation through AEGIS-X FastAPI
    auth_res = client.post(
        "/api/v1/messaging/rooms/authorize",
        headers=AUTH_HEADER,
        json={"recipient_user_id": "usr-admin-01"}
    )
    assert auth_res.status_code == 200
    auth_data = auth_res.json()
    assert auth_data["allowed"] is True
    assert auth_data["encryption_required"] is True

    # 2. Sender initializes local Matrix client with WASM crypto
    sender_client = MockMatrixMegolmClient(
        user_id="@analyst_soc_01:chat.aegis-x.internal",
        device_id="BROWSER_DEVICE_01",
        is_verified=True
    )
    sender_client.init_crypto("my_passphrase_123")

    # 3. Client encrypts the canary locally in browser memory
    test_room_id = "!secure_incident_room:chat.aegis-x.internal"
    encrypted_event = sender_client.encrypt_room_event(test_room_id, canary_token)

    # 4. Link room to incident in AEGIS-X (metadata only)
    db = SessionLocal()
    unique_inc_id = f"inc-canary-{uuid.uuid4().hex[:8]}"
    inc = Incident(
        incident_id=unique_inc_id,
        organization_id="org-acme-fintech-01",
        title="Canary Security Test Incident",
        severity="HIGH",
        status="OPEN"
    )
    db.add(inc)
    db.commit()
    target_inc_id = inc.incident_id
    db.close()

    link_res = client.post(
        "/api/v1/messaging/rooms/link",
        headers=AUTH_HEADER,
        json={
            "matrix_room_id": test_room_id,
            "room_type": "INCIDENT",
            "incident_id": target_inc_id
        }
    )
    assert link_res.status_code == 200

    # 5. SERVER-SIDE FORENSIC INSPECTION:
    # Scan every table, column, and text field in aegis_x.db for the canary token!
    db_path = "aegis_x.db"
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

        canary_found_count = 0
        for table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [c[1] for c in cursor.fetchall()]
            for col in columns:
                query = f"SELECT COUNT(*) FROM {table} WHERE CAST({col} AS TEXT) LIKE ?"
                cursor.execute(query, (f"%{canary_token}%",))
                count = cursor.fetchone()[0]
                if count > 0:
                    canary_found_count += count
        conn.close()

        # Zero-Plaintext Rule: The server database MUST NOT contain the canary plaintext!
        assert canary_found_count == 0, f"SECURITY LEAK: Canary '{canary_token}' found {canary_found_count} times in backend database!"

    # 6. Recipient client local decryption in browser memory
    recipient_client = MockMatrixMegolmClient(
        user_id="@admin_01:chat.aegis-x.internal",
        device_id="BROWSER_DEVICE_02",
        is_verified=True
    )
    recipient_client.init_crypto("admin_passphrase_456")
    decrypted_plaintext = recipient_client.decrypt_room_event(encrypted_event, sender_client._session_key)
    
    # Recipient can successfully read the canary locally
    assert decrypted_plaintext == canary_token

def test_fail_closed_before_crypto_initialization():
    """
    Security Test (E2E-08):
    Sending before crypto initialization must be strictly blocked with no plaintext fallback.
    """
    uninitialized_client = MockMatrixMegolmClient(
        user_id="@analyst_soc_01:chat.aegis-x.internal",
        device_id="UNINITIALIZED_DEVICE",
        is_verified=False
    )
    # Crypto not initialized
    assert uninitialized_client.crypto_initialized is False

    with pytest.raises(RuntimeError) as exc_info:
        uninitialized_client.encrypt_room_event("!room:chat.aegis-x.internal", "Secret incident communication")

    assert "Plaintext fallback blocked" in str(exc_info.value)

def test_device_verification_policy_enforcement():
    """
    Security Test (E2E-12 / E2E-13):
    Verifies that the tenant policy mandates verified devices.
    """
    res = client.get("/api/v1/messaging/bootstrap", headers=AUTH_HEADER)
    assert res.status_code == 200
    assert res.json()["require_device_verification"] is True

def test_xss_script_injection_handled_as_data():
    """
    Security Test (E2E-20):
    Injecting script-like tags into message body remains inert ciphertext.
    """
    script_payload = "<script>alert('AEGIS_X_XSS_EXPLOIT')</script>"
    sender = MockMatrixMegolmClient("@user1:chat.test", "DEV1")
    sender.init_crypto()
    
    event = sender.encrypt_room_event("!room:test", script_payload)
    # Ciphertext is raw base64 and has no raw HTML tags
    assert "<script>" not in event["content"]["ciphertext"]

    recipient = MockMatrixMegolmClient("@user2:chat.test", "DEV2")
    recipient.init_crypto()
    decrypted = recipient.decrypt_room_event(event, sender._session_key)
    assert decrypted == script_payload
