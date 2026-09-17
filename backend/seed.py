import hashlib
import hmac
import uuid
import datetime
from backend.database import engine, Base, SessionLocal
from backend.models import (
    Organization, User, Asset, AssetDependency, Identity, IdentityAssetAccess,
    IntelligenceSource, Vulnerability, AssetVulnerability, AuditEvent
)

def hash_pass(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def hash_identifier(identifier: str) -> str:
    return hmac.new(b"aegis_x_salt_key", identifier.lower().encode(), hashlib.sha256).hexdigest()[:16]

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Check if existing seed exists
    if db.query(Organization).first():
        db.close()
        return

    # 1. Organization
    org = Organization(
        organization_id="org-acme-fintech-01",
        name="Acme FinTech Ltd.",
        industry="Financial Services & Banking",
        country="India",
        risk_profile="HIGH",
        data_retention_days=365
    )
    db.add(org)

    # 2. Users
    admin_user = User(
        user_id="usr-admin-01",
        organization_id=org.organization_id,
        email="admin@acme.test",
        password_hash=hash_pass("AdminPass2026!"),
        role="Org Admin",
        mfa_enabled=True
    )
    soc_user = User(
        user_id="usr-soc-01",
        organization_id=org.organization_id,
        email="soc.analyst@acme.test",
        password_hash=hash_pass("SocPass2026!"),
        role="SOC Analyst L2",
        mfa_enabled=True
    )
    db.add_all([admin_user, soc_user])

    # 3. Assets
    assets_data = [
        {"id": "ast-erp-01", "name": "ERP-01 Core Enterprise Engine", "type": "APPLICATION", "crit": 10, "class": "RESTRICTED", "net": False, "dept": "Finance"},
        {"id": "ast-findb-01", "name": "FinanceDB Production Cluster", "type": "DATABASE", "crit": 10, "class": "RESTRICTED", "net": False, "dept": "Finance"},
        {"id": "ast-vpn-01", "name": "Corporate VPN Gateway", "type": "SERVER", "crit": 9, "class": "RESTRICTED", "net": True, "dept": "IT Infrastructure"},
        {"id": "ast-gitlab-01", "name": "GitLab Enterprise Code Repository", "type": "APPLICATION", "crit": 8, "class": "RESTRICTED", "net": False, "dept": "Engineering"},
        {"id": "ast-hrms-01", "name": "HRMS People Database", "type": "APPLICATION", "crit": 7, "class": "CONFIDENTIAL", "net": False, "dept": "HR"},
        {"id": "ast-cms-01", "name": "Marketing CMS Portal", "type": "APPLICATION", "crit": 5, "class": "PUBLIC", "net": True, "dept": "Marketing"},
        {"id": "ast-web-01", "name": "Acme Public Fintech Web", "type": "DOMAIN", "crit": 3, "class": "PUBLIC", "net": True, "dept": "Marketing"},
    ]

    asset_objects = {}
    for a in assets_data:
        ast = Asset(
            asset_id=a["id"],
            organization_id=org.organization_id,
            asset_type=a["type"],
            name=a["name"],
            hostname=f"{a['id']}.acme.internal",
            domain="acme.test",
            department_name=a["dept"],
            business_criticality=a["crit"],
            data_classification=a["class"],
            internet_exposed=a["net"],
            status="ACTIVE"
        )
        db.add(ast)
        asset_objects[a["id"]] = ast

    # 4. Asset Dependencies
    dependencies = [
        ("ast-erp-01", "ast-findb-01", "CONNECTS_TO", 10),
        ("ast-vpn-01", "ast-erp-01", "PROVIDES_ACCESS", 9),
        ("ast-gitlab-01", "ast-erp-01", "DEPLOYS_TO", 8),
        ("ast-web-01", "ast-cms-01", "USES_API", 4),
    ]
    for src, tgt, rel, crit in dependencies:
        db.add(AssetDependency(
            source_asset_id=src,
            target_asset_id=tgt,
            relationship_type=rel,
            criticality=crit
        ))

    # 5. Identities
    cfo_identity = Identity(
        identity_id="id-cfo-01",
        organization_id=org.organization_id,
        identity_type="EXECUTIVE",
        identifier_hash=hash_identifier("cfo@acme.test"),
        department_name="Finance",
        privilege_level=9,
        criticality=10
    )
    sales_identity = Identity(
        identity_id="id-sales-01",
        organization_id=org.organization_id,
        identity_type="EMPLOYEE",
        identifier_hash=hash_identifier("employee1@acme.test"),
        department_name="Sales",
        privilege_level=3,
        criticality=4
    )
    dev_identity = Identity(
        identity_id="id-dev-01",
        organization_id=org.organization_id,
        identity_type="EMPLOYEE",
        identifier_hash=hash_identifier("dev.lead@acme.test"),
        department_name="Engineering",
        privilege_level=8,
        criticality=8
    )
    db.add_all([cfo_identity, sales_identity, dev_identity])

    # 6. Identity Asset Access
    db.add(IdentityAssetAccess(identity_id=cfo_identity.identity_id, asset_id="ast-erp-01", privilege="SUPER_ADMIN"))
    db.add(IdentityAssetAccess(identity_id=cfo_identity.identity_id, asset_id="ast-findb-01", privilege="READ_WRITE"))
    db.add(IdentityAssetAccess(identity_id=dev_identity.identity_id, asset_id="ast-gitlab-01", privilege="ADMIN"))

    # 7. Intelligence Sources
    hibp = IntelligenceSource(source_id="src-hibp", source_name="HaveIBeenPwned API v3", source_type="HIBP", credibility_score=0.95)
    cti = IntelligenceSource(source_id="src-cti", source_name="Global Cyber Threat Intelligence Feed", source_type="CTI", credibility_score=0.90)
    cisa = IntelligenceSource(source_id="src-cisa", source_name="CISA KEV Catalog", source_type="CISA_KEV", credibility_score=0.99)
    db.add_all([hibp, cti, cisa])

    # 8. Vulnerabilities
    cve_vpn = Vulnerability(
        vulnerability_id="vuln-cve-2024-21887",
        cve_id="CVE-2024-21887",
        cvss_score=9.8,
        severity="CRITICAL",
        kev_known_exploited=True,
        description="Ivanti Connect Secure and Policy Secure command injection vulnerability actively exploited in the wild."
    )
    db.add(cve_vpn)

    db.add(AssetVulnerability(
        asset_id="ast-vpn-01",
        vulnerability_id=cve_vpn.vulnerability_id,
        status="OPEN",
        patch_available=True,
        internet_exposed=True,
        exploitability_score=9.5,
        risk_score=9.8
    ))

    # 9. Initial Cryptographic Hash-Chained Audit Entry
    init_audit = AuditEvent(
        organization_id=org.organization_id,
        actor_id=admin_user.user_id,
        action="SYSTEM_INIT",
        resource_type="PLATFORM",
        resource_id="AEGIS-X",
        ip_hash=hashlib.sha256(b"127.0.0.1").hexdigest()[:16],
        previous_event_hash="0000000000000000000000000000000000000000000000000000000000000000",
        event_hash=hashlib.sha256(b"AEGIS_X_INITIAL_GENESIS_BLOCK_2026").hexdigest()
    )
    db.add(init_audit)

    db.commit()
    db.close()
    print("Database successfully initialized and seeded with Acme FinTech Ltd. profile.")

if __name__ == "__main__":
    init_db()
