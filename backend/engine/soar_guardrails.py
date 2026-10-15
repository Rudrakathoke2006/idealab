import datetime
from typing import Dict, Any, List, Optional, Set

class SOARSafetyPolicyGate:
    """
    AEGIS-X Safe Automated Response & Policy Gate (Headline Research Feature)
    
    A formally specified policy gate that evaluates:
      - Independent evidence corroboration (anti-poisoning defenses)
      - Dynamic attribute-based protected resource tags (no hardcoded names)
      - Transitive graph-derived action collateral impact
      - Mandatory operational safety invariants (Last Admin, Core IdP)
      - Rate limits and action blast budgets per time window
      
    Decisions:
      - ALLOW_AUTOMATION: All prerequisites, invariants, and corroboration met.
      - REQUIRE_APPROVAL: High-impact action, single unverified feed, or threshold exceeded.
      - RECOMMEND_ONLY: Manual triage guidance only; automation not permitted.
      - DENY_AUTOMATION: Prohibited target or hard safety invariant violated.
    """

    DECISION_ALLOW = "ALLOW_AUTOMATION"
    DECISION_APPROVAL = "REQUIRE_APPROVAL"
    DECISION_RECOMMEND = "RECOMMEND_ONLY"
    DECISION_DENY = "DENY_AUTOMATION"

    def __init__(self):
        # Action history for rate limiting and blast budget: {tenant_id: [(timestamp, action_type)]}
        self._action_history: Dict[str, List[Tuple[datetime.datetime, str]]] = {}
        # Max automated containment actions allowed per 15-minute rolling window
        self.MAX_ACTIONS_PER_WINDOW = 4
        self.RATE_WINDOW_MINUTES = 15

    def normalize_identifier(self, identifier: str) -> str:
        """Normalizes email, UPN, or account identifier for robust comparison."""
        if not identifier:
            return ""
        clean = identifier.lower().strip()
        # Handle plus-addressing (e.g. user+security@domain.com -> user@domain.com)
        if "@" in clean:
            local, domain = clean.split("@", 1)
            if "+" in local:
                local = local.split("+")[0]
            clean = f"{local}@{domain}"
        return clean

    def _check_rate_limit(self, tenant_id: str) -> bool:
        """Verify action rate limit within rolling time window."""
        now = datetime.datetime.utcnow()
        cutoff = now - datetime.timedelta(minutes=self.RATE_WINDOW_MINUTES)
        history = self._action_history.get(tenant_id, [])
        # Filter to active window
        active_history = [entry for entry in history if entry[0] > cutoff]
        self._action_history[tenant_id] = active_history
        return len(active_history) < self.MAX_ACTIONS_PER_WINDOW

    def record_executed_action(self, tenant_id: str, action_type: str):
        """Record executed action into rate-limiting window."""
        now = datetime.datetime.utcnow()
        if tenant_id not in self._action_history:
            self._action_history[tenant_id] = []
        self._action_history[tenant_id].append((now, action_type))

    def evaluate_response_policy(
        self,
        action_type: str,
        target_attributes: Dict[str, Any],
        context: Dict[str, Any],
        tenant_id: str = "org-acme-fintech-01"
    ) -> Dict[str, Any]:
        """
        Evaluate full multi-attribute policy gate against candidate remediation action.
        """
        # 1. Tenant Isolation & Validation
        if not tenant_id or context.get("tenant_mismatch", False):
            return {
                "decision": self.DECISION_DENY,
                "reason_code": "TENANT_SECURITY_VIOLATION",
                "explanation": "Cross-tenant action boundary violation detected. Automated remediation denied.",
                "requires_approval": False,
                "allow_execution": False
            }

        # 2. Hard Safety Invariant 1: Preserve Administrative Recovery Quorum (Never Revoke Last Admin)
        is_admin_role = target_attributes.get("is_admin", False) or target_attributes.get("privilege_level", 0) >= 9
        total_active_admins = context.get("active_admin_count", 2)
        if "REVOKE" in action_type or "RESET" in action_type or "DISABLE" in action_type:
            if is_admin_role and total_active_admins <= 1:
                return {
                    "decision": self.DECISION_DENY,
                    "reason_code": "INVARIANT_VIOLATION_LAST_ADMIN",
                    "explanation": "Safety Invariant Violated: Target is the last recovery-capable administrator. Automated lockout blocked to prevent enterprise paralysis.",
                    "requires_approval": True,
                    "allow_execution": False
                }

        # 3. Hard Safety Invariant 2: Preserve Core IdP & Domain Controller Reachability
        target_type = target_attributes.get("asset_type", "").upper()
        is_idp_or_dc = (
            target_attributes.get("is_identity_provider", False) or
            target_attributes.get("is_domain_controller", False) or
            target_type in ["IDP", "DOMAIN_CONTROLLER", "KEY_MANAGEMENT"]
        )
        if "ISOLATE" in action_type or "CONTAIN" in action_type or "BLOCK" in action_type:
            if is_idp_or_dc:
                return {
                    "decision": self.DECISION_DENY,
                    "reason_code": "INVARIANT_VIOLATION_CORE_INFRASTRUCTURE",
                    "explanation": "Safety Invariant Violated: Target is core authentication infrastructure. Automated isolation blocked to prevent network-wide blackout.",
                    "requires_approval": True,
                    "allow_execution": False
                }

        # 4. Dynamic Attribute-Based Protection (Tier-1 Crown Jewels)
        is_crown_jewel = (
            target_attributes.get("is_crown_jewel", False) or
            target_attributes.get("criticality_tier", 3) == 1 or
            target_attributes.get("business_criticality", 0) >= 10
        )
        if is_crown_jewel and action_type in ["ISOLATE_HOST", "DISABLE_ACCOUNT", "REVOKE_ALL_SESSIONS"]:
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "PROTECTED_CROWN_JEWEL_APPROVAL_REQUIRED",
                "explanation": f"Target entity is flagged as Tier-1 Crown Jewel (Criticality: {target_attributes.get('business_criticality', 10)}/10). Analyst 2FA Approval Gate required.",
                "requires_approval": True,
                "allow_execution": False
            }

        # 5. Anti-Poisoning & Evidence Corroboration Gate
        # High impact actions require at least 2 independent corroborating sources OR source confidence >= 0.95
        independent_sources = context.get("independent_source_count", 1)
        source_confidence = context.get("source_confidence", 0.80)
        is_destructive_action = action_type in ["ISOLATE_HOST", "RESET_CREDENTIAL", "DISABLE_ACCOUNT"]

        if is_destructive_action and independent_sources < 2 and source_confidence < 0.95:
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "UNCONFIRMED_EVIDENCE_CORROBORATION_REQUIRED",
                "explanation": "Adversarial Anti-Poisoning Gate: Single uncorroborated feed report cannot trigger automated disruptive remediation. Requires manual confirmation.",
                "requires_approval": True,
                "allow_execution": False
            }

        # 6. Rate Limit & Blast Budget Check
        if not self._check_rate_limit(tenant_id):
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "RATE_LIMIT_BLAST_BUDGET_EXCEEDED",
                "explanation": f"Action rate limit exceeded ({self.MAX_ACTIONS_PER_WINDOW} actions within {self.RATE_WINDOW_MINUTES} mins). Human gate required to prevent mass disruption.",
                "requires_approval": True,
                "allow_execution": False
            }

        # 7. Action Collateral Impact Assessment
        collateral_affected_users = context.get("transitive_affected_users", 0)
        collateral_affected_services = context.get("transitive_affected_services", 0)
        collateral_impact_score = (collateral_affected_users * 2.0) + (collateral_affected_services * 5.0)

        if collateral_impact_score >= 50.0:
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "HIGH_COLLATERAL_IMPACT_APPROVAL_REQUIRED",
                "explanation": f"Remediation collateral impact score ({collateral_impact_score:.1f}) exceeds automated budget. Transitive users affected: {collateral_affected_users}, services: {collateral_affected_services}.",
                "requires_approval": True,
                "allow_execution": False
            }

        # 8. All Safety Invariants and Gates Satisfied -> Authorize Automated Execution
        return {
            "decision": self.DECISION_ALLOW,
            "reason_code": "AUTOMATION_POLICY_PERMITTED",
            "explanation": "All operational safety invariants, corroboration criteria, and rate limits satisfied. Automated SOAR execution authorized.",
            "requires_approval": False,
            "allow_execution": True,
            "rollback_supported": context.get("rollback_supported", True),
            "collateral_impact_score": collateral_impact_score
        }

soar_policy_gate = SOARSafetyPolicyGate()
