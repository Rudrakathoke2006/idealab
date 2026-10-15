from typing import Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from backend.models import User, Incident, MessagingIdentity
from .policy_service import policy_service
from .identity_service import identity_service
from .security_event_service import record_security_event

class AuthorizationService:
    def authorize_direct_conversation(
        self,
        db: Session,
        tenant_id: str,
        requester_user_id: str,
        recipient_user_id: str,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Endpoint C authorization logic:
        Validates organizational policy, tenant boundaries, and recipient status.
        Does NOT create rooms or touch message plaintext.
        """
        # 1. Check organizational messaging policy
        policy = policy_service.get_tenant_policy(db, tenant_id)
        if not policy.messaging_enabled:
            record_security_event(
                db=db, tenant_id=tenant_id, event_type="ACCESS_DENIED",
                actor_user_id=requester_user_id, request_id=request_id,
                details={"reason": "Messaging is disabled by organizational policy."}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Messaging is disabled by organizational policy."
            )

        if not policy.direct_messages_enabled:
            record_security_event(
                db=db, tenant_id=tenant_id, event_type="ACCESS_DENIED",
                actor_user_id=requester_user_id, request_id=request_id,
                details={"reason": "Direct messaging is disabled for this tenant."}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Direct messaging is disabled for this tenant."
            )

        # 2. Check requester status
        requester = db.query(User).filter(User.user_id == requester_user_id).first()
        if not requester or requester.status != "ACTIVE":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Requester account is inactive.")

        req_ident = identity_service.get_identity_by_user_id(db, tenant_id, requester_user_id)
        if req_ident and (not req_ident.enabled or req_ident.provisioning_status == "SUSPENDED"):
            record_security_event(
                db=db, tenant_id=tenant_id, event_type="ACCESS_DENIED",
                actor_user_id=requester_user_id, request_id=request_id,
                details={"reason": "Requester messaging privileges have been suspended."}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your secure messaging privileges have been suspended."
            )

        # 3. Check recipient existence
        recipient = db.query(User).filter(User.user_id == recipient_user_id).first()
        if not recipient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient not found or is not accessible."
            )

        # 4. Enforce tenant boundary
        if recipient.organization_id != tenant_id and not policy.allow_cross_tenant:
            record_security_event(
                db=db, tenant_id=tenant_id, event_type="CROSS_TENANT_ACCESS_BLOCKED",
                actor_user_id=requester_user_id, request_id=request_id,
                details={"recipient_user_id": recipient_user_id, "reason": "Cross-tenant messaging is prohibited."}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant messaging is prohibited by organizational security policy."
            )

        # 5. Check recipient messaging identity
        rec_ident = identity_service.get_identity_by_user_id(db, recipient.organization_id, recipient_user_id)
        if not rec_ident:
            rec_ident = identity_service.get_or_create_identity(db, recipient.organization_id, recipient_user_id)

        if not rec_ident.enabled or rec_ident.provisioning_status == "SUSPENDED":
            record_security_event(
                db=db, tenant_id=tenant_id, event_type="ACCESS_DENIED",
                actor_user_id=requester_user_id, request_id=request_id,
                details={"recipient_user_id": recipient_user_id, "reason": "Recipient messaging access is suspended."}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Recipient messaging access is currently inactive or suspended."
            )

        # 6. Record authorized audit event
        record_security_event(
            db=db, tenant_id=tenant_id, event_type="ROOM_AUTHORIZED",
            actor_user_id=requester_user_id, request_id=request_id,
            details={"recipient_user_id": recipient_user_id, "policy_version": policy.policy_version}
        )

        return {
            "allowed": True,
            "recipient_matrix_user_id": rec_ident.matrix_user_id,
            "recipient_user_id": recipient.user_id,
            "encryption_required": True,
            "require_device_verification": policy.require_device_verification,
            "policy_version": policy.policy_version
        }

    def authorize_incident_room(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        incident_id: str
    ) -> Incident:
        """
        Validates that user has authorized access to attach or inspect an incident-scoped room.
        """
        policy = policy_service.get_tenant_policy(db, tenant_id)
        if not policy.incident_rooms_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Incident-associated messaging rooms are disabled by policy."
            )

        incident = db.query(Incident).filter(
            Incident.incident_id == incident_id,
            Incident.organization_id == tenant_id
        ).first()

        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found in your tenant organization."
            )

        return incident

authorization_service = AuthorizationService()
