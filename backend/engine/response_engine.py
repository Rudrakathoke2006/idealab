from typing import Dict, List, Any

class ResponseRecommendationEngine:
    """
    Automated Incident Response Recommendation Engine
    Generates context-aware P0 / P1 / P2 actionable playbooks based on exposure category.
    """

    def generate_playbook(self, category: str, context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        playbook = []

        cat_upper = category.upper()
        if "CREDENTIAL" in cat_upper or "PASSWORD" in cat_upper:
            playbook = [
                {"priority": "P0", "action_type": "RESET_CREDENTIAL", "description": "Reset compromised user credentials immediately via IAM/Active Directory.", "automation_supported": True},
                {"priority": "P0", "action_type": "REVOKE_SESSIONS", "description": "Terminate all active OAuth, Web, and VPN sessions for the target identity.", "automation_supported": True},
                {"priority": "P0", "action_type": "ENABLE_MFA", "description": "Enforce mandatory FIDO2/TOTP step-up authentication.", "automation_supported": True},
                {"priority": "P1", "action_type": "AUDIT_LOGS", "description": "Review authentication logs for past 14 days for anomalous IP accesses.", "automation_supported": False},
                {"priority": "P2", "action_type": "REVIEW_PRIVILEGES", "description": "Perform access review to ensure least privilege principle.", "automation_supported": False}
            ]
        elif "API" in cat_upper or "TOKEN" in cat_upper or "KEY" in cat_upper:
            playbook = [
                {"priority": "P0", "action_type": "ROTATE_KEY", "description": "Rotate exposed API token key pair in Payment Gateway.", "automation_supported": True},
                {"priority": "P0", "action_type": "REVOKE_OLD_KEY", "description": "Revoke legacy secret string in API Gateway configuration.", "automation_supported": True},
                {"priority": "P1", "action_type": "INSPECT_GATEWAY_LOGS", "description": "Inspect API Gateway logs for unauthorized write payload requests.", "automation_supported": False},
                {"priority": "P1", "action_type": "REDUCE_SCOPE", "description": "Restrict token authorization scope to read-only endpoints.", "automation_supported": True}
            ]
        elif "VULNERABILITY" in cat_upper or "CVE" in cat_upper or "VPN" in cat_upper:
            playbook = [
                {"priority": "P0", "action_type": "PATCH_CVE", "description": "Apply vendor security patch for CISA KEV active vulnerability.", "automation_supported": True},
                {"priority": "P0", "action_type": "RESTRICT_EXPOSURE", "description": "Temporarily restrict internet exposure via Security Group NACL.", "automation_supported": True},
                {"priority": "P1", "action_type": "APPLY_WAF_RULE", "description": "Deploy virtual patch rule on Web Application Firewall (WAF).", "automation_supported": True},
                {"priority": "P2", "action_type": "VERIFY_IOCS", "description": "Scan endpoint memory and logs for Indicators of Compromise (IoCs).", "automation_supported": False}
            ]
        else:
            playbook = [
                {"priority": "P0", "action_type": "CONTAIN_ASSET", "description": "Isolate affected network node from enterprise network zone.", "automation_supported": True},
                {"priority": "P1", "action_type": "INVESTIGATE_ANOMALY", "description": "Trigger SOC analyst forensic triage investigation.", "automation_supported": False},
                {"priority": "P2", "action_type": "UPDATE_THREAT_FEED", "description": "Add malicious IP indicator to firewall blocklist.", "automation_supported": True}
            ]

        return playbook

response_engine = ResponseRecommendationEngine()
