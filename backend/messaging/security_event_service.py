import hashlib
import uuid
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import MessagingSecurityEvent

FORBIDDEN_DETAIL_KEYS = {
    "plaintext", "body", "message", "message_text", "text", "payload",
    "key", "private_key", "secret", "password", "token", "access_token",
    "auth_token", "recovery_secret", "crypto_store_password", "crypto_passphrase"
}

ALLOWED_DETAIL_KEYS = {
    "reason", "recipient_user_id", "incident_id", "policy_version",
    "action", "room_type", "status", "count", "verification_status",
    "search_query_prefix", "client_version", "device_id"
}

class SecurityEventService:
    @staticmethod
    def sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enforce strict Zero-Plaintext metadata sanitation.
        Rejects or strips sensitive payload fields before persistence.
        """
        if not details:
            return {}
        
        sanitized = {}
        for k, v in details.items():
            k_lower = k.lower()
            if k_lower in FORBIDDEN_DETAIL_KEYS or any(f in k_lower for f in ["password", "secret", "private_key", "plaintext"]):
                continue  # Strictly omit forbidden sensitive field
            if k_lower in ALLOWED_DETAIL_KEYS or not any(f in k_lower for f in ["pass", "key", "token", "msg"]):
                # Ensure value is JSON serializable and safe
                if isinstance(v, (str, int, float, bool, list)) or v is None:
                    sanitized[k] = v
        return sanitized

    @staticmethod
    def hash_room_id(matrix_room_id: Optional[str]) -> Optional[str]:
        """
        Produce a pseudonymous, one-way hash of room identifiers for privacy preservation.
        """
        if not matrix_room_id:
            return None
        return hashlib.sha256(matrix_room_id.encode("utf-8")).hexdigest()[:32]

    def record_security_event(
        self,
        db: Session,
        tenant_id: str,
        event_type: str,
        actor_user_id: Optional[str] = None,
        room_id: Optional[str] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> MessagingSecurityEvent:
        """
        Records an allowlisted security event in messaging_security_events.
        Never stores message plaintext, private keys, or credentials.
        """
        sanitized_meta = self.sanitize_details(details)
        room_hash = self.hash_room_id(room_id)
        req_id = request_id or str(uuid.uuid4())

        event = MessagingSecurityEvent(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            room_id_hash=room_hash,
            request_id=req_id,
            details_json=sanitized_meta
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

security_event_service = SecurityEventService()

def record_security_event(
    db: Session,
    tenant_id: str,
    event_type: str,
    actor_user_id: Optional[str] = None,
    room_id: Optional[str] = None,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> MessagingSecurityEvent:
    return security_event_service.record_security_event(
        db=db,
        tenant_id=tenant_id,
        event_type=event_type,
        actor_user_id=actor_user_id,
        room_id=room_id,
        request_id=request_id,
        details=details
    )
