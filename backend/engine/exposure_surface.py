from typing import Dict, List, Any

class ExposureSurfaceEngine:
    """
    Pipeline E - Exposure Surface & Vulnerability Weak-Point Engine
    Detects exposed attack surfaces, misconfigurations, unpatched CVEs, and CISA KEV status.
    """

    WEAKNESS_CATALOG = {
        "VULNERABLE_SOFTWARE": {"severity": 9.0, "impact": "Critical CVE vulnerability detected on asset software."},
        "CISA_KEV_EXPLOITED": {"severity": 10.0, "impact": "Active exploitation in the wild listed in CISA KEV catalog."},
        "INTERNET_EXPOSURE": {"severity": 8.0, "impact": "Asset directly accessible from public internet without network protection."},
        "MFA_ABSENT": {"severity": 8.5, "impact": "Multi-Factor Authentication absent on privileged identity/asset access."},
        "EXCESS_PRIVILEGES": {"severity": 7.5, "impact": "Identity retains excessive admin privileges over business critical systems."},
        "OLD_CREDENTIAL_ROTATION": {"severity": 6.0, "impact": "Credential key or password expired rotation threshold (> 180 days)."},
        "CLOUD_PUBLIC_BUCKET": {"severity": 9.0, "impact": "Publicly accessible cloud storage bucket containing sensitive documents."}
    }

    def evaluate_asset_weakness(
        self,
        asset_name: str,
        asset_criticality: int,
        internet_exposed: bool,
        mfa_enabled: bool,
        has_cve: bool,
        cvss_score: float = 0.0,
        cisa_kev: bool = False,
        privilege_level: int = 5
    ) -> Dict[str, Any]:
        """
        Evaluate single asset exposure surface weaknesses.
        """
        detected_weaknesses = []
        base_weakness_score = 0.0

        if has_cve:
            weak = self.WEAKNESS_CATALOG["VULNERABLE_SOFTWARE"].copy()
            weak["cvss"] = cvss_score
            detected_weaknesses.append(weak)
            base_weakness_score += (cvss_score / 10.0) * 30.0

        if cisa_kev:
            weak = self.WEAKNESS_CATALOG["CISA_KEV_EXPLOITED"].copy()
            detected_weaknesses.append(weak)
            base_weakness_score += 35.0

        if internet_exposed:
            weak = self.WEAKNESS_CATALOG["INTERNET_EXPOSURE"].copy()
            detected_weaknesses.append(weak)
            base_weakness_score += 20.0

        if not mfa_enabled:
            weak = self.WEAKNESS_CATALOG["MFA_ABSENT"].copy()
            detected_weaknesses.append(weak)
            base_weakness_score += 15.0

        if privilege_level >= 8:
            weak = self.WEAKNESS_CATALOG["EXCESS_PRIVILEGES"].copy()
            detected_weaknesses.append(weak)
            base_weakness_score += 10.0

        # Cap score at 100.0
        final_weakness_score = min(100.0, base_weakness_score * (asset_criticality / 10.0))

        return {
            "asset_name": asset_name,
            "asset_criticality": asset_criticality,
            "weakness_score": round(final_weakness_score, 1),
            "weakness_count": len(detected_weaknesses),
            "weaknesses": detected_weaknesses
        }

exposure_surface_engine = ExposureSurfaceEngine()
