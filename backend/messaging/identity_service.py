import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import User, MessagingIdentity, Organization
from backend.config import settings
from .security_event_service import record_security_event

class IdentityService:
    def sanitize_localpart(self, raw: str) -> str:
        """
        Produce a valid Matrix localpart slug (lowercase alphanumeric, dot, underscore, hyphen).
        """
        slug = re.sub(r"[^a-zA-Z0-9._=-]", "_", raw.lower())
        return slug[:64]

    def get_or_create_identity(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        matrix_user_id: Optional[str] = None
    ) -> MessagingIdentity:
        """
        Map an authenticated AEGIS-X user to a Matrix identity.
        Strictly never stores access tokens, device private keys, or recovery secrets.
        """
        # Verify user belongs to tenant
        user = db.query(User).filter(User.user_id == user_id, User.organization_id == tenant_id).first()
        if not user:
            raise ValueError(f"User {user_id} does not exist in tenant {tenant_id}")

        identity = db.query(MessagingIdentity).filter(
            MessagingIdentity.tenant_id == tenant_id,
            MessagingIdentity.user_id == user_id
        ).first()

        if identity:
            return identity

        if not matrix_user_id:
            email_prefix = user.email.split("@")[0] if user.email else user_id
            localpart = self.sanitize_localpart(email_prefix)
            matrix_user_id = f"@{localpart}:{settings.MATRIX_SERVER_NAME}"

            # Ensure uniqueness
            existing_mx = db.query(MessagingIdentity).filter(
                MessagingIdentity.matrix_user_id == matrix_user_id
            ).first()
            if existing_mx:
                matrix_user_id = f"@{localpart}_{user_id[:6]}:{settings.MATRIX_SERVER_NAME}"

        identity = MessagingIdentity(
            tenant_id=tenant_id,
            user_id=user_id,
            matrix_user_id=matrix_user_id,
            enabled=True,
            provisioning_status="ACTIVE"
        )
        db.add(identity)
        db.commit()
        db.refresh(identity)

        record_security_event(
            db=db,
            tenant_id=tenant_id,
            actor_user_id=user_id,
            event_type="IDENTITY_PROVISIONED",
            details={"status": "ACTIVE", "recipient_user_id": user_id}
        )
        return identity

    def get_identity_by_user_id(
        self,
        db: Session,
        tenant_id: str,
        user_id: str
    ) -> Optional[MessagingIdentity]:
        return db.query(MessagingIdentity).filter(
            MessagingIdentity.tenant_id == tenant_id,
            MessagingIdentity.user_id == user_id
        ).first()

    def get_identity_by_matrix_user_id(
        self,
        db: Session,
        matrix_user_id: str
    ) -> Optional[MessagingIdentity]:
        return db.query(MessagingIdentity).filter(
            MessagingIdentity.matrix_user_id == matrix_user_id
        ).first()

    def suspend_identity(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        actor_user_id: Optional[str] = None,
        reason: str = "Administrative suspension"
    ) -> MessagingIdentity:
        """
        Suspends messaging access for a user.
        Offboarding hook: instantly halts message authorization.
        """
        identity = self.get_identity_by_user_id(db, tenant_id, user_id)
        if not identity:
            identity = self.get_or_create_identity(db, tenant_id, user_id)

        identity.enabled = False
        identity.provisioning_status = "SUSPENDED"
        db.commit()
        db.refresh(identity)

        record_security_event(
            db=db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id or user_id,
            event_type="USER_SUSPENDED",
            details={"recipient_user_id": user_id, "reason": reason}
        )
        return identity

    def reactivate_identity(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        actor_user_id: Optional[str] = None
    ) -> MessagingIdentity:
        identity = self.get_identity_by_user_id(db, tenant_id, user_id)
        if not identity:
            identity = self.get_or_create_identity(db, tenant_id, user_id)

        identity.enabled = True
        identity.provisioning_status = "ACTIVE"
        db.commit()
        db.refresh(identity)

        record_security_event(
            db=db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id or user_id,
            event_type="USER_REACTIVATED",
            details={"recipient_user_id": user_id, "status": "ACTIVE"}
        )
        return identity

    def search_recipients(
        self,
        db: Session,
        tenant_id: str,
        query: Optional[str] = None,
        requester_user_id: Optional[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Tenant-scoped recipient directory search.
        Strict Rules:
        - Only active users within the requester's tenant.
        - Never leaks users from other organizations.
        - Rate/quantity capped to prevent directory harvesting.
        - Never includes passwords, hashes, or private keys.
        """
        safe_limit = min(max(1, limit), 50)
        user_query = db.query(User).filter(
            User.organization_id == tenant_id,
            User.status == "ACTIVE"
        )

        if requester_user_id:
            user_query = user_query.filter(User.user_id != requester_user_id)

        if query:
            q_clean = query.strip().lower()
            user_query = user_query.filter(
                (User.email.ilike(f"%{q_clean}%")) | (User.role.ilike(f"%{q_clean}%"))
            )

        users = user_query.limit(safe_limit).all()
        results = []

        for u in users:
            # Fetch or ensure identity
            ident = db.query(MessagingIdentity).filter(
                MessagingIdentity.tenant_id == tenant_id,
                MessagingIdentity.user_id == u.user_id
            ).first()

            if not ident:
                ident = self.get_or_create_identity(db, tenant_id, u.user_id)

            if ident.enabled and ident.provisioning_status == "ACTIVE":
                # Compute friendly display name
                display_name = u.email.split("@")[0].replace(".", " ").title()
                if u.role:
                    display_name += f" ({u.role})"

                results.append({
                    "user_id": u.user_id,
                    "display_name": display_name,
                    "email": u.email,
                    "matrix_user_id": ident.matrix_user_id
                })

        return results

identity_service = IdentityService()
