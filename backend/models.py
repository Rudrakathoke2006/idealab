import uuid
import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.database import Base

def gen_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.datetime.utcnow()

class Organization(Base):
    __tablename__ = "organizations"

    organization_id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    industry = Column(String, default="Finance")
    country = Column(String, default="India")
    risk_profile = Column(String, default="HIGH")
    data_retention_days = Column(Integer, default=365)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    users = relationship("User", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")
    identities = relationship("Identity", back_populates="organization")
    incidents = relationship("Incident", back_populates="organization")

class User(Base):
    __tablename__ = "users"

    user_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.organization_id"), nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="SOC Analyst L2")
    status = Column(String, default="ACTIVE")
    mfa_enabled = Column(Boolean, default=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="users")

class Asset(Base):
    __tablename__ = "assets"

    asset_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.organization_id"), nullable=False)
    asset_type = Column(String, nullable=False) # SERVER, DATABASE, API, APPLICATION, CLOUD_RESOURCE, ENDPOINT, DOMAIN, EMAIL_DOMAIN, SAAS, NETWORK_DEVICE
    name = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    ip_token = Column(String, nullable=True)
    environment = Column(String, default="PRODUCTION")
    owner_user_id = Column(String, nullable=True)
    department_name = Column(String, default="Finance")
    business_criticality = Column(Integer, default=8) # 1-10 scale
    data_classification = Column(String, default="RESTRICTED") # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    internet_exposed = Column(Boolean, default=False)
    status = Column(String, default="ACTIVE")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="assets")
    vulnerabilities = relationship("AssetVulnerability", back_populates="asset")

class AssetDependency(Base):
    __tablename__ = "asset_dependencies"

    dependency_id = Column(String, primary_key=True, default=gen_uuid)
    source_asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    target_asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    relationship_type = Column(String, default="CONNECTS_TO") # CONNECTS_TO, HOSTS, USES_API, STORES_DATA
    criticality = Column(Integer, default=8)

class Identity(Base):
    __tablename__ = "identities"

    identity_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.organization_id"), nullable=False)
    identity_type = Column(String, default="EMPLOYEE") # EMPLOYEE, SERVICE_ACCOUNT, ADMIN, EXECUTIVE
    identifier_hash = Column(String, index=True, nullable=False) # HMAC of email/username
    department_name = Column(String, default="Finance")
    privilege_level = Column(Integer, default=5) # 1-10 scale
    criticality = Column(Integer, default=7)
    status = Column(String, default="ACTIVE")
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="identities")

class IdentityAssetAccess(Base):
    __tablename__ = "identity_asset_access"

    id = Column(String, primary_key=True, default=gen_uuid)
    identity_id = Column(String, ForeignKey("identities.identity_id"), nullable=False)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    access_type = Column(String, default="READ_WRITE")
    privilege = Column(String, default="ADMIN")
    last_verified_at = Column(DateTime, default=utc_now)

class IntelligenceSource(Base):
    __tablename__ = "intelligence_sources"

    source_id = Column(String, primary_key=True, default=gen_uuid)
    source_name = Column(String, nullable=False)
    source_type = Column(String, default="HIBP") # HIBP, CTI, OSINT, CISA_KEV, NVD
    credibility_score = Column(Float, default=0.9) # 0.0 - 1.0
    enabled = Column(Boolean, default=True)
    poll_interval = Column(Integer, default=3600)
    last_success_at = Column(DateTime, nullable=True)

class ExposureEvent(Base):
    __tablename__ = "exposure_events"

    exposure_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.organization_id"), nullable=False)
    source_id = Column(String, ForeignKey("intelligence_sources.source_id"), nullable=True)
    source_name = Column(String, default="HIBP / CTI Feed")
    source_event_hash = Column(String, unique=True, index=True, nullable=False)
    exposed_entity = Column(String, nullable=False, default="cfo@acme.test")
    exposure_date = Column(DateTime, default=utc_now)
    detected_at = Column(DateTime, default=utc_now)
    exposure_type = Column(String, nullable=False) # CREDENTIAL, API_KEY, TOKEN, PII, FINANCIAL, SOURCE_CODE
    data_sensitivity = Column(Float, default=8.0) # 1-10 scale
    record_count = Column(Integer, default=1)
    source_credibility = Column(Float, default=0.95) # 0.0 - 1.0 (Credibility of source)
    source_confidence = Column(Float, default=9.0) # 0 - 10 scale (Separate evidence confidence)
    validation_status = Column(String, default="MATCHED") # MATCHED, UNMATCHED, OUT_OF_SCOPE
    relevance_score = Column(Float, default=0.8)
    status = Column(String, default="UNPROCESSED") # UNPROCESSED, CORRELATED, RESOLVED
    created_at = Column(DateTime, default=utc_now)

    entities = relationship("ExposureEntity", back_populates="exposure")

class ExposureEntity(Base):
    __tablename__ = "exposure_entities"

    entity_id = Column(String, primary_key=True, default=gen_uuid)
    exposure_id = Column(String, ForeignKey("exposure_events.exposure_id"), nullable=False)
    entity_type = Column(String, nullable=False) # EMAIL, DOMAIN, SECRET_TYPE, DEPARTMENT, IP
    tokenized_value = Column(String, nullable=False)
    confidence = Column(Float, default=1.0)
    matched_identity_id = Column(String, ForeignKey("identities.identity_id"), nullable=True)
    matched_asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=True)

    exposure = relationship("ExposureEvent", back_populates="entities")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    vulnerability_id = Column(String, primary_key=True, default=gen_uuid)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    cvss_score = Column(Float, default=7.5)
    severity = Column(String, default="HIGH")
    kev_known_exploited = Column(Boolean, default=False) # CISA KEV flag
    description = Column(Text, nullable=True)
    published_at = Column(DateTime, default=utc_now)

class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"

    asset_vulnerability_id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.vulnerability_id"), nullable=False)
    detected_at = Column(DateTime, default=utc_now)
    status = Column(String, default="OPEN") # OPEN, PATCHED, MITIGATED
    patch_available = Column(Boolean, default=True)
    internet_exposed = Column(Boolean, default=False)
    exploitability_score = Column(Float, default=8.0)
    risk_score = Column(Float, default=8.5)

    asset = relationship("Asset", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability")

class SecurityEvent(Base):
    __tablename__ = "security_events"

    event_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.organization_id"), nullable=False)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=True)
    identity_id = Column(String, ForeignKey("identities.identity_id"), nullable=True)
    event_type = Column(String, nullable=False) # LOGIN_FAILED, ANOMALOUS_DOWNLOAD, PRIVILEGE_CHANGE, IMPOSSIBLE_TRAVEL
    event_time = Column(DateTime, default=utc_now)
    source = Column(String, default="INTERNAL_TELEMETRY")
    severity = Column(String, default="MEDIUM")
    confidence = Column(Float, default=0.85)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now)

class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.organization_id"), nullable=False)
    title = Column(String, nullable=False)
    category = Column(String, default="Credential Exposure") # Credential Exposure, Vulnerability Exploitation, Behavioral Anomaly, Supply Chain
    severity = Column(String, default="CRITICAL") # Informational, Low, Medium, High, Critical
    severity_score = Column(Float, default=93.0) # 0-100 scale
    confidence_score = Column(Float, default=88.0) # 0-100 scale
    blast_radius_score = Column(Float, default=85.0) # 0-100 scale
    business_impact_score = Column(Float, default=90.0) # 0-100 scale
    status = Column(String, default="Open") # Open, Investigating, Contained, Resolved, Closed
    assigned_to = Column(String, nullable=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    created_at = Column(DateTime, default=utc_now)
    resolved_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="incidents")
    assessments = relationship("RiskAssessment", back_populates="incident")
    recommendations = relationship("ResponseRecommendation", back_populates="incident")
    attack_paths = relationship("AttackPath", back_populates="incident")

class IncidentExposure(Base):
    __tablename__ = "incident_exposures"

    id = Column(String, primary_key=True, default=gen_uuid)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=False)
    exposure_id = Column(String, ForeignKey("exposure_events.exposure_id"), nullable=False)

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    assessment_id = Column(String, primary_key=True, default=gen_uuid)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=False)
    model_version = Column(String, default="v1.0-hybrid-xgboost")
    
    data_sensitivity = Column(Float, default=9.0)
    exploitability = Column(Float, default=8.5)
    asset_criticality = Column(Float, default=10.0)
    freshness = Column(Float, default=9.5)
    source_confidence = Column(Float, default=9.0)
    blast_radius = Column(Float, default=8.5)
    vulnerability_score = Column(Float, default=9.2)
    threat_context = Column(Float, default=8.0)
    historical_score = Column(Float, default=7.0)

    rule_score = Column(Float, default=91.5)
    ml_probability = Column(Float, default=0.94)
    final_score = Column(Float, default=93.0)
    confidence = Column(Float, default=88.0)
    created_at = Column(DateTime, default=utc_now)

    incident = relationship("Incident", back_populates="assessments")
    explanations = relationship("RiskExplanation", back_populates="assessment")

class RiskExplanation(Base):
    __tablename__ = "risk_explanations"

    explanation_id = Column(String, primary_key=True, default=gen_uuid)
    assessment_id = Column(String, ForeignKey("risk_assessments.assessment_id"), nullable=False)
    factor_name = Column(String, nullable=False)
    factor_value = Column(String, nullable=False)
    contribution = Column(Float, nullable=False) # e.g. +18.4
    reason = Column(String, nullable=False)

    assessment = relationship("RiskAssessment", back_populates="explanations")

class AttackPath(Base):
    __tablename__ = "attack_paths"

    path_id = Column(String, primary_key=True, default=gen_uuid)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=False)
    path_probability = Column(Float, default=0.87)
    impact_score = Column(Float, default=92.0)
    path_length = Column(Integer, default=4)
    status = Column(String, default="ACTIVE")
    created_at = Column(DateTime, default=utc_now)

    incident = relationship("Incident", back_populates="attack_paths")
    nodes = relationship("AttackPathNode", back_populates="attack_path")

class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    path_node_id = Column(String, primary_key=True, default=gen_uuid)
    path_id = Column(String, ForeignKey("attack_paths.path_id"), nullable=False)
    sequence_no = Column(Integer, nullable=False)
    entity_type = Column(String, nullable=False) # CREDENTIAL, IDENTITY, APPLICATION, DATABASE, VENDOR
    entity_name = Column(String, nullable=False)
    relationship_type = Column(String, nullable=False) # ACCESSES, CONNECTS_TO, EXPLOITS

    attack_path = relationship("AttackPath", back_populates="nodes")

class ResponseRecommendation(Base):
    __tablename__ = "response_recommendations"

    recommendation_id = Column(String, primary_key=True, default=gen_uuid)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=False)
    priority = Column(String, default="P0") # P0, P1, P2
    action_type = Column(String, nullable=False) # RESET_CREDENTIAL, REVOKE_SESSION, PATCH_CVE, ENABLE_MFA, ROTATE_KEY
    description = Column(String, nullable=False)
    automation_supported = Column(Boolean, default=True)
    status = Column(String, default="PENDING") # PENDING, IN_PROGRESS, COMPLETED, SKIPPED
    created_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)

    incident = relationship("Incident", back_populates="recommendations")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    audit_id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, nullable=False)
    actor_id = Column(String, nullable=False)
    action = Column(String, nullable=False) # INCIDENT_CLOSED, SEVERITY_CHANGED, PLAYBOOK_EXECUTED
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    request_id = Column(String, default=gen_uuid)
    ip_hash = Column(String, nullable=False)
    timestamp = Column(DateTime, default=utc_now)
    
    # Hash Chaining cryptographic fields
    before_hash = Column(String, nullable=True)
    after_hash = Column(String, nullable=True)
    previous_event_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False)
