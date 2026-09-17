import datetime
import uuid
from typing import Dict, Any

class OCSFNormalizer:
    """
    OCSF v1.1.0 (Open Cybersecurity Schema Framework) Event Normalizer.
    Converts raw vendor payloads (Okta, Sentinel, HIBP, Wiz, CrowdStrike)
    into standardized OCSF Security Event objects.
    """

    CLASS_AUTHENTICATION = 3002
    CLASS_SECURITY_FINDING = 2001
    CLASS_VULNERABILITY = 2002

    @staticmethod
    def normalize_credential_leak(raw_payload: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
        """Convert credential exposure dump into OCSF Security Finding (Class 2001)."""
        identity = raw_payload.get("identity", "unknown@domain.com")
        data_sensitivity = float(raw_payload.get("data_sensitivity", 9.0))

        return {
            "activity_id": 1, # Create Finding
            "class_uid": OCSFNormalizer.CLASS_SECURITY_FINDING,
            "category_uid": 2, # Findings
            "severity_id": 4 if data_sensitivity >= 8.0 else 3,
            "severity": "CRITICAL" if data_sensitivity >= 8.0 else "HIGH",
            "metadata": {
                "version": "1.1.0",
                "product": {"vendor_name": "HIBP / CTI Feed", "name": "Breach Intelligence"},
                "tenant_id": tenant_id,
                "event_id": str(uuid.uuid4())
            },
            "finding_info": {
                "title": f"Exposed Credential Leaked for {identity}",
                "desc": "Compromised cleartext or hashed password detected on CTI monitoring stream.",
                "types": ["CREDENTIAL_LEAK", "IDENTITY_EXPOSURE"]
            },
            "user": {
                "email_addr": identity,
                "type": "User Account"
            },
            "time": datetime.datetime.utcnow().isoformat() + "Z"
        }

    @staticmethod
    def normalize_vuln_finding(raw_payload: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
        """Convert vulnerability scan into OCSF Vulnerability Finding (Class 2002)."""
        asset_name = raw_payload.get("asset", "Infrastructure Node")
        cvss_score = float(raw_payload.get("cvss_score", 9.8))

        return {
            "activity_id": 1,
            "class_uid": OCSFNormalizer.CLASS_VULNERABILITY,
            "category_uid": 2,
            "severity_id": 4 if cvss_score >= 9.0 else 3,
            "severity": "CRITICAL" if cvss_score >= 9.0 else "HIGH",
            "metadata": {
                "version": "1.1.0",
                "product": {"vendor_name": "Wiz / Tenable / Qualys", "name": "Vulnerability Scanner"},
                "tenant_id": tenant_id,
                "event_id": str(uuid.uuid4())
            },
            "vulnerabilities": [
                {
                    "cve_id": raw_payload.get("cve_id", "CVE-2024-21887"),
                    "cvss_score": cvss_score,
                    "cisa_kev": raw_payload.get("cisa_kev", True),
                    "affected_asset": asset_name
                }
            ],
            "time": datetime.datetime.utcnow().isoformat() + "Z"
        }

ocsf_normalizer = OCSFNormalizer()
