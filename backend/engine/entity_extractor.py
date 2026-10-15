import re
import hmac
import hashlib
from typing import Dict, List, Any, Optional

class EntityExtractor:
    """
    Pipeline B - Entity Extraction, Sensitive Data Pseudonymization & Domain Matching
    
    Academic Defenses:
      1. Domain-Spoofing Immunity: Strict host boundary matching (rejects lookalikes like acme.test.evil.com).
      2. Plus-Addressing Normalization: Normalizes aliases (cfo+alert@domain.com -> cfo@domain.com).
      3. Irreversible Pseudonymization: HMAC-SHA256 tokenization with configurable salt.
      4. Tenant-Aware Organization Scope Matching.
    """
    
    EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b')
    DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    API_KEY_REGEX = re.compile(r'\b(?:sec_key_[0-9a-zA-Z]{24}|akia[0-9a-z]{16}|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b', re.IGNORECASE)
    DEPARTMENTS = ["finance", "hr", "engineering", "sales", "operations", "executive", "it", "security"]

    def __init__(self, hmac_salt: str = "aegis_x_token_salt_2026"):
        self.hmac_salt = hmac_salt.encode('utf-8')

    def tokenize(self, value: str, prefix: str = "tok") -> str:
        """Pseudonymize sensitive identifier into a deterministic non-reversible token."""
        h = hmac.new(self.hmac_salt, value.lower().strip().encode('utf-8'), hashlib.sha256).hexdigest()
        return f"{prefix}_{h[:16]}"

    def normalize_email(self, email: str) -> str:
        """Strip plus-addressing and lowercase email."""
        clean = email.lower().strip()
        if "@" in clean:
            local, domain = clean.split("@", 1)
            if "+" in local:
                local = local.split("+")[0]
            clean = f"{local}@{domain}"
        return clean

    def match_enterprise_identity(
        self,
        identifier: str,
        org_domains: List[str] = None,
        db_identities: List[str] = None
    ) -> Dict[str, Any]:
        """
        Enterprise Identity Matching with Strict Domain Boundary Defense.
        Prevents subdomain spoofing (e.g. 'cfo@acme.test.attacker.com' will NOT match 'acme.test').
        """
        org_domains = [d.lower().strip() for d in (org_domains or ["acme.test", "company.com", "acme.internal"])]
        identifier_clean = self.normalize_email(identifier)

        matched_by_domain = False
        matched_domain = None

        if "@" in identifier_clean:
            ident_domain = identifier_clean.split("@")[-1]
            for dom in org_domains:
                # Exact domain match OR strict enterprise subdomain match (e.g. dept.acme.test)
                if ident_domain == dom or ident_domain.endswith(f".{dom}"):
                    matched_by_domain = True
                    matched_domain = dom
                    break
        else:
            # Domain-only identifier
            for dom in org_domains:
                if identifier_clean == dom or identifier_clean.endswith(f".{dom}"):
                    matched_by_domain = True
                    matched_domain = dom
                    break

        # Check DB identity list if provided
        matched_by_db = False
        if db_identities:
            matched_by_db = any(identifier_clean == self.normalize_email(id_val) for id_val in db_identities)

        is_matched = matched_by_domain or matched_by_db

        return {
            "identifier": identifier,
            "normalized_identifier": identifier_clean,
            "is_matched": is_matched,
            "validation_status": "MATCHED" if is_matched else "UNMATCHED",
            "matched_domain": matched_domain,
            "match_reason": (
                f"Strict enterprise domain boundary match on '{matched_domain}'"
                if matched_by_domain
                else ("Database identity hash match" if matched_by_db else "Entity does not belong to authorized tenant scope")
            )
        }

    def extract(self, raw_input: str) -> Dict[str, Any]:
        """Extract entities and return pseudonymized payload."""
        entities: List[Dict[str, Any]] = []

        # 1. Emails
        emails = self.EMAIL_REGEX.findall(raw_input)
        for email in set(emails):
            norm = self.normalize_email(email)
            domain = norm.split('@')[-1]
            entities.append({
                "type": "EMAIL",
                "raw_preview": f"{norm[:3]}***@{domain}",
                "token": self.tokenize(norm, "e"),
                "domain": domain,
                "confidence": 0.98
            })

        # 2. Domains
        domains = self.DOMAIN_REGEX.findall(raw_input)
        for dom in set(domains):
            dom_clean = dom.lower()
            if not any(e.get("domain") == dom_clean for e in entities if "domain" in e):
                entities.append({
                    "type": "DOMAIN",
                    "value": dom_clean,
                    "confidence": 0.95
                })

        # 3. API Keys / Secrets
        api_keys = self.API_KEY_REGEX.findall(raw_input)
        for key in set(api_keys):
            entities.append({
                "type": "API_KEY",
                "token": self.tokenize(key, "sec"),
                "secret_type": "API_KEY_OR_TOKEN",
                "confidence": 0.99
            })

        # 4. Department Mapping
        for dept in self.DEPARTMENTS:
            if dept in raw_input.lower():
                entities.append({
                    "type": "DEPARTMENT",
                    "value": dept.upper(),
                    "confidence": 0.85
                })

        return {
            "entity_count": len(entities),
            "entities": entities
        }

entity_extractor = EntityExtractor()
