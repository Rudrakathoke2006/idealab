from typing import Dict, Any, List

class SOARSafetyGuardrails:
    """
    SOAR Remediation Safety Guardrail & Approval Engine.
    Enforces 3-Tier execution policy:
      - RECOMMEND_ONLY: Manual dashboard review required.
      - APPROVE_THEN_EXECUTE: Analyst 2FA approval gate required.
      - AUTO_EXECUTE: Opt-in automated execution with safety pre-flight check.

    Contains a strict Break-Glass Exclusion List protecting executive identities
    (CEO, CFO, Board Members) and Domain Controllers / Payment Clusters.
    """

    EXCLUSION_IDENTITIES = [
        "ceo@acme.test", "ceo@company.com",
        "cfo@acme.test", "cfo@company.com",
        "admin@domain.controller", "svc_domain_controller"
    ]

    EXCLUSION_ASSETS = [
        "Domain Controller 01", "Core Payment Cluster", "Primary Active Directory"
    ]

    EXECUTION_MODE_RECOMMEND = "RECOMMEND_ONLY"
    EXECUTION_MODE_APPROVE = "APPROVE_THEN_EXECUTE"
    EXECUTION_MODE_AUTO = "AUTO_EXECUTE"

    def evaluate_remediation_safety(
        self,
        action_type: str,
        target_identity: str,
        target_asset: str,
        execution_mode: str = "APPROVE_THEN_EXECUTE"
    ) -> Dict[str, Any]:
        """
        Evaluate safety parameters and return approval status & blast radius check.
        """
        identity_lower = target_identity.lower()
        asset_lower = target_asset.lower()

        # Check Break-Glass Exclusion List
        for ex_id in self.EXCLUSION_IDENTITIES:
            if ex_id.lower() in identity_lower:
                return {
                    "allowed": False,
                    "reason": f"BREAK_GLASS_EXCLUSION: Target identity '{target_identity}' is protected by executive exclusion list. Automated remediation blocked.",
                    "requires_manual_override": True,
                    "execution_mode": self.EXECUTION_MODE_RECOMMEND
                }

        for ex_asset in self.EXCLUSION_ASSETS:
            if ex_asset.lower() in asset_lower:
                return {
                    "allowed": False,
                    "reason": f"BREAK_GLASS_EXCLUSION: Target asset '{target_asset}' is critical core infrastructure. Automated isolation blocked.",
                    "requires_manual_override": True,
                    "execution_mode": self.EXECUTION_MODE_RECOMMEND
                }

        # Handle Execution Mode Policies
        if execution_mode == self.EXECUTION_MODE_RECOMMEND:
            return {
                "allowed": True,
                "reason": "Policy set to RECOMMEND_ONLY. Action surfaced for analyst triage.",
                "requires_approval_gate": False,
                "auto_execution_triggered": False
            }

        elif execution_mode == self.EXECUTION_MODE_APPROVE:
            return {
                "allowed": True,
                "reason": "Action approved for execution via Analyst 2FA Approval Gate.",
                "requires_approval_gate": True,
                "auto_execution_triggered": False
            }

        elif execution_mode == self.EXECUTION_MODE_AUTO:
            return {
                "allowed": True,
                "reason": "Action authorized for automated SOAR execution.",
                "requires_approval_gate": False,
                "auto_execution_triggered": True
            }

        return {"allowed": False, "reason": "Invalid execution mode specified."}

soar_guardrails = SOARSafetyGuardrails()
