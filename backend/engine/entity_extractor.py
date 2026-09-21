import re
import hmac
import hashlib
from typing import Dict, List, Any

class EntityExtractor:
    """
    Pipeline B - Entity Extraction, Sensitive Data Tokenizer & Enterprise Domain Matcher
    Identifies emails, domains, credential indicators, API keys, AWS identifiers, and departments.
    Tokenizes sensitive values using HMAC/SHA-256 and matches against organization domains/identities.
    """
    
    EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    API_KEY_REGEX = re.compile(r'\b(?:sec_key_[0-9a-zA-Z]{24}|akia[0-9a-z]{16}|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b', re.IGNORECASE)
    DEPARTMENTS = ["finance", "hr", "engineering", "sales", "operations", "exec", "cfo", "it"]

    def __init__(self, hmac_salt: str = "aegis_x_token_salt_2026"):
        self.hmac_salt = hmac_salt.encode('utf-8')

    def tokenize(self, value: str, prefix: str = "tok") -> str:
        """Tokenize sensitive identifier into a deterministic non-reversible token."""
        h = hmac.new(self.hmac_salt, value.lower().strip().encode('utf-8'), hashlib.sha256).hexdigest()
        return f"{prefix}_{h[:12]}"

    def match_enterprise_identity(
        self,
        identifier: str,
        org_domains: List[str] = None,
        db_identities: List[str] = None
    ) -> Dict[str, Any]:
        """
        Enterprise Identity Matching: Checks if ingested exposure entity belongs to organization.
        Only matched exposures proceed to risk scoring.
        """
        org_domains = org_domains or ["acme.test", "company.com", "acme.internal"]
        identifier_clean = identifier.lower().strip()

        # Domain check
        matched_by_domain = any(identifier_clean.endswith(f"@{dom}") or identifier_clean.endswith(f".{dom}") or identifier_clean == dom for dom in org_domains)

        # Hash/Identifier list check
        matched_by_db = False
        if db_identities:
            matched_by_db = any(identifier_clean in id_val.lower() for id_val in db_identities)

        is_matched = matched_by_domain or matched_by_db

        return {
            "identifier": identifier,
            "is_matched": is_matched,
            "validation_status": "MATCHED" if is_matched else "UNMATCHED",
            "match_reason": "Domain suffix match against organization assets" if matched_by_domain else ("Database identity hash match" if matched_by_db else "External entity does not belong to enterprise scope")
        }

    def extract(self, raw_input: str) -> Dict[str, Any]:
        """Extract entities and return tokenized payload."""
        entities: List[Dict[str, Any]] = []

        # 1. Emails
        emails = self.EMAIL_REGEX.findall(raw_input)
        for email in set(emails):
            domain = email.split('@')[-1]
            entities.append({
                "type": "EMAIL",
                "token": self.tokenize(email, "e"),
                "domain": domain,
                "confidence": 0.98
            })

        # 2. Domains
        domains = self.DOMAIN_REGEX.findall(raw_input)
        for dom in set(domains):
            if not any(e.get("domain") == dom for e in entities if "domain" in e):
                entities.append({
                    "type": "DOMAIN",
                    "value": dom.lower(),
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

        # 4. Password / Credential Indicators
        if any(term in raw_input.lower() for term in ["password", "passhash", "shadow", "auth_secret", "ntlm"]):
            entities.append({
                "type": "SECRET_TYPE",
                "value": "password",
                "confidence": 0.90
            })

        # 5. Department Mapping
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
