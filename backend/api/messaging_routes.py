import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User, Incident, MessagingPolicy
from backend.config import settings
from backend.messaging.identity_service import identity_service
from backend.messaging.authorization_service import authorization_service
from backend.messaging.room_link_service import room_link_service
from backend.messaging.policy_service import policy_service
from backend.messaging.security_event_service import record_security_event

router = APIRouter(prefix="/messaging", tags=["AEGIS-X Secure Incident Messaging"])

# ---------------------------------------------------------------------------
# Authentication Dependency
# ---------------------------------------------------------------------------
def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts and authenticates the current AEGIS-X user.
    Supports standard Bearer tokens (`aegis_jwt_token_{user_id}`) and `X-User-ID` headers.
    """
    user: Optional[User] = None

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        if token.startswith("aegis_jwt_token_"):
            uid = token[len("aegis_jwt_token_"):]
            user = db.query(User).filter(User.user_id == uid).first()
        elif token:
            # Fallback search by ID or email
            user = db.query(User).filter((User.user_id == token) | (User.email == token)).first()

    if not user and x_user_id:
        user = db.query(User).filter(User.user_id == x_user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided or are invalid."
        )

    if user.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated or suspended."
        )

    return user


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------
class BootstrapResponse(BaseModel):
    enabled: bool
    homeserver_url: str
    matrix_user_id: str
    encryption_required: bool
    require_device_verification: bool
    policy_version: str

class RecipientItem(BaseModel):
    user_id: str
    display_name: str
    matrix_user_id: str
    email: Optional[str] = None

class RecipientsResponse(BaseModel):
    items: List[RecipientItem]

class AuthorizeRoomRequest(BaseModel):
    recipient_user_id: str

class AuthorizeRoomResponse(BaseModel):
    allowed: bool
    recipient_matrix_user_id: str
    recipient_user_id: str
    encryption_required: bool
    require_device_verification: bool
    policy_version: str

class LinkRoomRequest(BaseModel):
    matrix_room_id: str
    room_type: str = "INCIDENT"
    incident_id: Optional[str] = None

class LinkRoomResponse(BaseModel):
    status: str
    link_id: str
    matrix_room_id: str
    room_type: str
    incident_id: Optional[str] = None
    policy_version: str

class IncidentRoomMetadataResponse(BaseModel):
    link_id: str
    matrix_room_id: str
    incident_id: str
    room_type: str
    policy_version: str
    encryption_required: bool
    require_device_verification: bool
    created_at: Optional[str] = None

class UpdatePolicyRequest(BaseModel):
    messaging_enabled: Optional[bool] = None
    direct_messages_enabled: Optional[bool] = None
    incident_rooms_enabled: Optional[bool] = None
    require_device_verification: Optional[bool] = None
    allow_cross_tenant: Optional[bool] = None


# ---------------------------------------------------------------------------
# Endpoint A — Get messaging configuration
# ---------------------------------------------------------------------------
@router.get("/bootstrap", response_model=BootstrapResponse)
def get_messaging_bootstrap(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns client messaging configuration and user's Matrix identity.
    Strictly never returns Matrix admin credentials, private keys, or plaintext messages.
    """
    tenant_id = current_user.organization_id
    policy = policy_service.get_tenant_policy(db, tenant_id)
    identity = identity_service.get_or_create_identity(db, tenant_id, current_user.user_id)

    return BootstrapResponse(
        enabled=policy.messaging_enabled and identity.enabled and identity.provisioning_status == "ACTIVE",
        homeserver_url=settings.MATRIX_HOMESERVER_URL,
        matrix_user_id=identity.matrix_user_id,
        encryption_required=True,
        require_device_verification=policy.require_device_verification,
        policy_version=policy.policy_version
    )


# ---------------------------------------------------------------------------
# Endpoint B — Search authorized recipients
# ---------------------------------------------------------------------------
@router.get("/recipients", response_model=RecipientsResponse)
def search_authorized_recipients(
    q: Optional[str] = Query(None, description="Search term for display name or email"),
    limit: int = Query(20, ge=1, le=50, description="Results pagination limit"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Searches authorized messaging recipients within the authenticated user's tenant boundary.
    Rate-limited and scoped strictly to prevent directory harvesting.
    """
    tenant_id = current_user.organization_id
    policy = policy_service.get_tenant_policy(db, tenant_id)
    if not policy.messaging_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Messaging is disabled for your organization."
        )

    results = identity_service.search_recipients(
        db=db,
        tenant_id=tenant_id,
        query=q,
        requester_user_id=current_user.user_id,
        limit=limit
    )

    items = [
        RecipientItem(
            user_id=r["user_id"],
            display_name=r["display_name"],
            matrix_user_id=r["matrix_user_id"],
            email=r["email"]
        )
        for r in results
    ]
    return RecipientsResponse(items=items)


# ---------------------------------------------------------------------------
# Endpoint C — Authorize a direct conversation
# ---------------------------------------------------------------------------
@router.post("/rooms/authorize", response_model=AuthorizeRoomResponse)
def authorize_direct_conversation(
    payload: AuthorizeRoomRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Authorizes a secure direct conversation between two tenant users.
    Does NOT create a Matrix room or handle message contents.
    """
    tenant_id = current_user.organization_id
    decision = authorization_service.authorize_direct_conversation(
        db=db,
        tenant_id=tenant_id,
        requester_user_id=current_user.user_id,
        recipient_user_id=payload.recipient_user_id
    )

    return AuthorizeRoomResponse(
        allowed=decision["allowed"],
        recipient_matrix_user_id=decision["recipient_matrix_user_id"],
        recipient_user_id=decision["recipient_user_id"],
        encryption_required=decision["encryption_required"],
        require_device_verification=decision["require_device_verification"],
        policy_version=decision["policy_version"]
    )


# ---------------------------------------------------------------------------
# Endpoint D — Associate a room with an incident
# ---------------------------------------------------------------------------
@router.post("/rooms/link", response_model=LinkRoomResponse)
def link_room_to_incident(
    payload: LinkRoomRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Attaches a Matrix room reference to an AEGIS-X incident.
    Validates tenant ownership and permissions; does not store message plaintext.
    """
    tenant_id = current_user.organization_id
    link = room_link_service.link_room(
        db=db,
        tenant_id=tenant_id,
        user_id=current_user.user_id,
        matrix_room_id=payload.matrix_room_id,
        room_type=payload.room_type,
        incident_id=payload.incident_id
    )

    return LinkRoomResponse(
        status="LINKED",
        link_id=link.id,
        matrix_room_id=link.matrix_room_id,
        room_type=link.room_type,
        incident_id=link.incident_id,
        policy_version=link.policy_version
    )


# ---------------------------------------------------------------------------
# Endpoint E — Retrieve incident-room metadata
# ---------------------------------------------------------------------------
@router.get("/incidents/{incident_id}/room", response_model=IncidentRoomMetadataResponse)
@router.get("/incidents/{incident_id}/messaging-room", response_model=IncidentRoomMetadataResponse)
def get_incident_messaging_room(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns authorized incident room reference and security policy metadata.
    Enforces incident access authorization; does not return messages or keys.
    """
    tenant_id = current_user.organization_id
    meta = room_link_service.get_incident_room(
        db=db,
        tenant_id=tenant_id,
        user_id=current_user.user_id,
        incident_id=incident_id
    )
    return IncidentRoomMetadataResponse(**meta)


# ---------------------------------------------------------------------------
# Policy Management & Security Audit Endpoints
# ---------------------------------------------------------------------------
@router.get("/policy")
def get_policy(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant_id = current_user.organization_id
    policy = policy_service.get_tenant_policy(db, tenant_id)
    return {
        "tenant_id": policy.tenant_id,
        "messaging_enabled": policy.messaging_enabled,
        "direct_messages_enabled": policy.direct_messages_enabled,
        "incident_rooms_enabled": policy.incident_rooms_enabled,
        "require_device_verification": policy.require_device_verification,
        "allow_cross_tenant": policy.allow_cross_tenant,
        "policy_version": policy.policy_version,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None
    }

@router.put("/policy")
def update_policy(
    payload: UpdatePolicyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant_id = current_user.organization_id
    dump_fn = getattr(payload, "model_dump", payload.dict)
    updated = policy_service.update_tenant_policy(db, tenant_id, dump_fn(exclude_unset=True))
    record_security_event(
        db=db, tenant_id=tenant_id, actor_user_id=current_user.user_id,
        event_type="POLICY_UPDATED", details={"policy_version": updated.policy_version}
    )
    return {"status": "UPDATED", "policy_version": updated.policy_version}

@router.post("/users/{target_user_id}/suspend")
def suspend_user_messaging(
    target_user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant_id = current_user.organization_id
    identity = identity_service.suspend_identity(
        db=db, tenant_id=tenant_id, user_id=target_user_id, actor_user_id=current_user.user_id
    )
    return {"status": "SUSPENDED", "user_id": target_user_id, "matrix_user_id": identity.matrix_user_id}

@router.post("/users/{target_user_id}/reactivate")
def reactivate_user_messaging(
    target_user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant_id = current_user.organization_id
    identity = identity_service.reactivate_identity(
        db=db, tenant_id=tenant_id, user_id=target_user_id, actor_user_id=current_user.user_id
    )
    return {"status": "ACTIVE", "user_id": target_user_id, "matrix_user_id": identity.matrix_user_id}

@router.get("/security-events")
def get_security_events(
    limit: int = Query(25, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns recent privacy-preserving security event records.
    Contains strictly allowlisted metadata, no plaintext or key material.
    """
    from backend.models import MessagingSecurityEvent
    tenant_id = current_user.organization_id
    events = db.query(MessagingSecurityEvent).filter(
        MessagingSecurityEvent.tenant_id == tenant_id
    ).order_by(MessagingSecurityEvent.created_at.desc()).limit(limit).all()

    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "actor_user_id": e.actor_user_id,
            "room_id_hash": e.room_id_hash,
            "request_id": e.request_id,
            "details": e.details_json,
            "created_at": e.created_at.isoformat() if e.created_at else None
        }
        for e in events
    ]
