from typing import Dict, List, Any, Optional
from backend.engine.soar_guardrails import soar_policy_gate

class ResponseRecommendationEngine:
    """
    AEGIS-X Context-Aware Actionable Response Engine
    
    Generates typed candidate remediation playbooks with explicit preconditions,
    postconditions, reversibility declarations, and evaluated policy decisions.
    """

    def generate_playbook(
        self,
        category: str,
        context: Dict[str, Any] = None,
        target_attributes: Dict[str, Any] = None,
        tenant_id: str = "org-acme-fintech-01"
    ) -> List[Dict[str, Any]]:
        context = context or {}
        target_attributes = target_attributes or {}

        cat_upper = category.upper()
        raw_actions = []

        if "CREDENTIAL" in cat_upper or "PASSWORD" in cat_upper:
            raw_actions = [
                {
                    "action_type": "RESET_CREDENTIAL",
                    "priority": "P0",
                    "description": "Reset compromised user credentials via IAM/Identity Provider.",
                    "is_reversible": True,
                    "preconditions": ["identity_exists", "idp_reachable"],
                    "postcondition_check": "verify_credential_rotation"
                },
                {
                    "action_type": "REVOKE_SESSIONS",
                    "priority": "P0",
                    "description": "Terminate all active OAuth, Web, and VPN sessions for the target identity.",
                    "is_reversible": False,
                    "preconditions": ["active_sessions_present"],
                    "postcondition_check": "verify_zero_active_tokens"
                },
                {
                    "action_type": "ENABLE_MFA",
                    "priority": "P0",
                    "description": "Enforce mandatory FIDO2/TOTP step-up authentication.",
                    "is_reversible": True,
                    "preconditions": ["identity_active"],
                    "postcondition_check": "verify_mfa_enforced"
                },
                {
                    "action_type": "AUDIT_LOGS",
                    "priority": "P1",
                    "description": "Review authentication logs for past 14 days for anomalous IP accesses.",
                    "is_reversible": True,
                    "preconditions": ["log_retention_active"],
                    "postcondition_check": "logs_indexed"
                }
            ]
        elif "API" in cat_upper or "TOKEN" in cat_upper or "KEY" in cat_upper:
            raw_actions = [
                {
                    "action_type": "ROTATE_KEY",
                    "priority": "P0",
                    "description": "Rotate exposed API token key pair in Payment Gateway.",
                    "is_reversible": True,
                    "preconditions": ["kms_active"],
                    "postcondition_check": "verify_key_rotated"
                },
                {
                    "action_type": "REVOKE_OLD_KEY",
                    "priority": "P0",
                    "description": "Revoke legacy secret string in API Gateway configuration.",
                    "is_reversible": False,
                    "preconditions": ["new_key_propagated"],
                    "postcondition_check": "verify_old_key_inactive"
                }
            ]
        elif "VULNERABILITY" in cat_upper or "CVE" in cat_upper or "VPN" in cat_upper:
            raw_actions = [
                {
                    "action_type": "RESTRICT_EXPOSURE",
                    "priority": "P0",
                    "description": "Temporarily restrict internet exposure via Security Group NACL.",
                    "is_reversible": True,
                    "preconditions": ["firewall_online"],
                    "postcondition_check": "verify_port_closed"
                },
                {
                    "action_type": "PATCH_CVE",
                    "priority": "P0",
                    "description": "Apply vendor security patch for CISA KEV active vulnerability.",
                    "is_reversible": True,
                    "preconditions": ["patch_available"],
                    "postcondition_check": "verify_version_updated"
                }
            ]
        else:
            raw_actions = [
                {
                    "action_type": "CONTAIN_ASSET",
                    "priority": "P0",
                    "description": "Isolate affected network node from enterprise network zone.",
                    "is_reversible": True,
                    "preconditions": ["edr_agent_online"],
                    "postcondition_check": "verify_network_isolation"
                }
            ]

        # Evaluate Policy Gate for each candidate action
        playbook = []
        for a in raw_actions:
            policy_eval = soar_policy_gate.evaluate_response_policy(
                action_type=a["action_type"],
                target_attributes=target_attributes,
                context=context,
                tenant_id=tenant_id
            )
            playbook.append({
                "action_type": a["action_type"],
                "priority": a["priority"],
                "description": a["description"],
                "automation_supported": policy_eval["allow_execution"],
                "policy_decision": policy_eval["decision"],
                "reason_code": policy_eval["reason_code"],
                "policy_explanation": policy_eval["explanation"],
                "is_reversible": a["is_reversible"],
                "status": "PENDING"
            })

        return playbook

response_engine = ResponseRecommendationEngine()
