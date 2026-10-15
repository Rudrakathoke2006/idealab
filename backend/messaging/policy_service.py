from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import MessagingPolicy
from backend.config import settings

class PolicyService:
    def get_tenant_policy(self, db: Session, tenant_id: str) -> MessagingPolicy:
        """
        Retrieves the tenant's organizational messaging policy.
        If no policy exists yet, provisions a secure default policy.
        """
        policy = db.query(MessagingPolicy).filter(MessagingPolicy.tenant_id == tenant_id).first()
        if not policy:
            policy = MessagingPolicy(
                tenant_id=tenant_id,
                messaging_enabled=settings.AEGIS_MESSAGING_ENABLED,
                direct_messages_enabled=True,
                incident_rooms_enabled=True,
                require_device_verification=settings.MESSAGING_REQUIRE_DEVICE_VERIFICATION,
                allow_cross_tenant=settings.MESSAGING_ALLOW_CROSS_TENANT,
                policy_version=settings.MESSAGING_POLICY_VERSION
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        return policy

    def update_tenant_policy(self, db: Session, tenant_id: str, updates: Dict[str, Any]) -> MessagingPolicy:
        """
        Updates organizational policy for tenant.
        """
        policy = self.get_tenant_policy(db, tenant_id)
        allowed_fields = [
            "messaging_enabled", "direct_messages_enabled", "incident_rooms_enabled",
            "require_device_verification", "allow_cross_tenant", "policy_version"
        ]
        for field in allowed_fields:
            if field in updates and updates[field] is not None:
                setattr(policy, field, updates[field])
        
        db.commit()
        db.refresh(policy)
        return policy

policy_service = PolicyService()
