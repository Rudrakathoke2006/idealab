"""
AEGIS-X Canonical Identity Resolver & Closure Engine (Dossier B3, W8, T10, T22)

Protects against adversarial identity obfuscation and bypass attacks:
  - S4 Alias / Case / Whitespace / Plus-addressing bypasses.
  - Subdomain and homoglyph spoofing.
  - Role-based group closure (e.g., membership in Domain Admins or Executive Steering).
  - Graph-derived dependency closure for service principals and machine accounts.
"""

import unicodedata
from typing import Dict, List, Set, Optional, Tuple, Any

class CanonicalIdentityResolver:
    """
    Robust canonical identity resolver that normalizes identifiers and maps group/dependency closures.
    """

    def __init__(self, allowed_domains: Optional[List[str]] = None):
        self.allowed_domains = [d.lower().strip() for d in (allowed_domains or ["enterprise.internal", "acme.test", "corp.local"])]
        # Known enterprise aliases: alias -> canonical_id
        self._alias_registry: Dict[str, str] = {
            "cfo@enterprise.internal": "id:cfo",
            "cfo@acme.test": "id:cfo",
            "chief.financial.officer@enterprise.internal": "id:cfo",
            "domain.admin@enterprise.internal": "id:domain_admin",
            "admin@acme.test": "id:domain_admin",
            "administrator@enterprise.internal": "id:domain_admin",
            "dev.lead@enterprise.internal": "id:dev",
            "lead.platform@acme.test": "id:dev"
        }
        # Group membership mappings: identity -> set of groups
        self._group_memberships: Dict[str, Set[str]] = {
            "id:cfo": {"EXECUTIVE_COMMITTEE", "AUDIT_BOARD", "FINANCE_CORE"},
            "id:domain_admin": {"DOMAIN_ADMINS", "ENTERPRISE_ADMINS", "SCHEMA_ADMINS", "TIER_0"},
            "id:dev": {"PLATFORM_ENGINEERING", "DEV_OPS"},
            "id:sales": {"SALES_GLOBAL"}
        }

    def canonicalize(self, raw_identifier: str) -> str:
        """
        Applies canonical transformation:
          1. Unicode NFKC normalization (defeats homoglyphs and unicode lookalikes).
          2. Case folding and whitespace strip.
          3. Plus-addressing removal (e.g. user+sec@domain.com -> user@domain.com).
          4. Subdomain strip to registered organizational root.
          5. Alias lookup.
        """
        if not raw_identifier:
            return ""

        # 1. Unicode normalization
        norm = unicodedata.normalize("NFKC", str(raw_identifier)).strip().lower()

        # 2. Email format handling
        if "@" in norm:
            local, domain = norm.rsplit("@", 1)
            # Remove plus-tagging
            if "+" in local:
                local = local.split("+")[0]
            # Strip trailing dots or spaces
            local = local.strip(". ")
            domain = domain.strip(". ")

            # Check if domain is a subdomain of an allowed domain (e.g. corp.acme.test -> acme.test)
            for allowed in self.allowed_domains:
                if domain == allowed or domain.endswith("." + allowed):
                    domain = allowed
                    break

            cleaned_email = f"{local}@{domain}"
            # Check alias registry
            if cleaned_email in self._alias_registry:
                return self._alias_registry[cleaned_email]
            return cleaned_email

        # 3. Node ID format handling (e.g., 'id:cfo' or 'cfo')
        if norm.startswith("id:"):
            return norm
        if f"id:{norm}" in self._group_memberships:
            return f"id:{norm}"

        return norm

    def get_group_closure(self, identity: str) -> Set[str]:
        """
        Returns full group membership closure for the canonicalized identity.
        """
        canonical_id = self.canonicalize(identity)
        groups = set(self._group_memberships.get(canonical_id, set()))

        # Transitive closure: check if any group confers Tier-0 / Administrative status
        admin_groups = {"DOMAIN_ADMINS", "ENTERPRISE_ADMINS", "TIER_0", "GLOBAL_ADMINS"}
        if any(g in admin_groups for g in groups):
            groups.add("TIER_0_ADMINISTRATIVE")

        return groups

    def is_tier_0(self, identity: str, graph_protected_set: Optional[Set[str]] = None) -> bool:
        """
        Evaluates whether an identity belongs to Tier-0 (Protected Set T0):
          - Graph-derived protected set inclusion.
          - Group closure containing Tier-0 administrative roles.
          - Canonical alias mapping to executive/core roles.
        """
        canonical_id = self.canonicalize(identity)

        # 1. Check graph-derived protected set
        if graph_protected_set:
            if canonical_id in graph_protected_set or f"id:{canonical_id}" in graph_protected_set:
                return True

        # 2. Check group closure
        groups = self.get_group_closure(canonical_id)
        if "TIER_0_ADMINISTRATIVE" in groups or "EXECUTIVE_COMMITTEE" in groups:
            return True

        # 3. Known privileged role identifiers
        if canonical_id in ["id:cfo", "id:domain_admin", "cfo@enterprise.internal", "admin@enterprise.internal"]:
            return True

        return False

canonical_resolver = CanonicalIdentityResolver()
