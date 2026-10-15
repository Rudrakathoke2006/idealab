from typing import Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from backend.models import MessagingRoomLink
from .policy_service import policy_service
from .authorization_service import authorization_service
from .security_event_service import record_security_event

class RoomLinkService:
    def link_room(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        matrix_room_id: str,
        room_type: str = "INCIDENT",
        incident_id: Optional[str] = None
    ) -> MessagingRoomLink:
        """
        Endpoint D — Associate a Matrix room with an incident.
        Creates an AEGIS-X metadata reference. Never receives or stores message plaintext.
        """
        policy = policy_service.get_tenant_policy(db, tenant_id)

        if room_type == "INCIDENT":
            if not incident_id:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="incident_id is required for INCIDENT room type."
                )
            # Verify incident ownership and permissions
            authorization_service.authorize_incident_room(
                db=db, tenant_id=tenant_id, user_id=user_id, incident_id=incident_id
            )

        # Check existing link for tenant and room
        existing = db.query(MessagingRoomLink).filter(
            MessagingRoomLink.tenant_id == tenant_id,
            MessagingRoomLink.matrix_room_id == matrix_room_id
        ).first()

        if existing:
            existing.room_type = room_type
            existing.incident_id = incident_id
            existing.policy_version = policy.policy_version
            db.commit()
            db.refresh(existing)
            link = existing
        else:
            link = MessagingRoomLink(
                tenant_id=tenant_id,
                matrix_room_id=matrix_room_id,
                room_type=room_type,
                incident_id=incident_id,
                created_by_user_id=user_id,
                policy_version=policy.policy_version
            )
            db.add(link)
            db.commit()
            db.refresh(link)

        record_security_event(
            db=db,
            tenant_id=tenant_id,
            actor_user_id=user_id,
            event_type="ROOM_LINKED",
            room_id=matrix_room_id,
            details={
                "room_type": room_type,
                "incident_id": incident_id,
                "policy_version": policy.policy_version
            }
        )
        return link

    def get_incident_room(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        incident_id: str
    ) -> Dict[str, Any]:
        """
        Endpoint E — Retrieve incident-room metadata.
        Returns the authorized room reference and policy metadata.
        Never returns messages or decryption keys.
        """
        # Validate incident access
        authorization_service.authorize_incident_room(
            db=db, tenant_id=tenant_id, user_id=user_id, incident_id=incident_id
        )
        policy = policy_service.get_tenant_policy(db, tenant_id)

        link = db.query(MessagingRoomLink).filter(
            MessagingRoomLink.tenant_id == tenant_id,
            MessagingRoomLink.incident_id == incident_id,
            MessagingRoomLink.archived_at.is_(None)
        ).first()

        if not link:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No secure messaging room is currently linked to this incident."
            )

        return {
            "link_id": link.id,
            "matrix_room_id": link.matrix_room_id,
            "incident_id": link.incident_id,
            "room_type": link.room_type,
            "policy_version": link.policy_version,
            "encryption_required": True,
            "require_device_verification": policy.require_device_verification,
            "created_at": link.created_at.isoformat() if link.created_at else None
        }

room_link_service = RoomLinkService()
