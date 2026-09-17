from typing import List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr

class TokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    role: str

class UserLoginSchema(BaseModel):
    email: str
    password: str

class OrganizationSchema(BaseModel):
    organization_id: str
    name: str
    industry: str
    country: str
    risk_profile: str

    class Config:
        from_attributes = True

class AssetSchema(BaseModel):
    asset_id: str
    asset_type: str
    name: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    department_name: str
    business_criticality: int
    data_classification: str
    internet_exposed: bool
    status: str

    class Config:
        from_attributes = True

class AssetCreateSchema(BaseModel):
    name: str
    asset_type: str = "SERVER"
    department_name: str = "Finance"
    business_criticality: int = 8
    data_classification: str = "RESTRICTED"
    internet_exposed: bool = False
    hostname: Optional[str] = None
    domain: Optional[str] = None
    status: str = "ACTIVE"


class IncidentOverviewSchema(BaseModel):
    incident_id: str
    title: str
    category: str
    severity: str
    severity_score: float
    confidence_score: float
    blast_radius_score: float
    business_impact_score: float
    status: str
    assigned_to: Optional[str] = None
    first_seen: datetime

    class Config:
        from_attributes = True

class RiskExplanationSchema(BaseModel):
    explanation_id: str
    factor_name: str
    factor_value: str
    contribution: float
    reason: str

    class Config:
        from_attributes = True

class RiskAssessmentSchema(BaseModel):
    assessment_id: str
    model_version: str
    data_sensitivity: float
    exploitability: float
    asset_criticality: float
    freshness: float
    source_confidence: float
    blast_radius: float
    vulnerability_score: float
    threat_context: float
    historical_score: float
    rule_score: float
    ml_probability: float
    final_score: float
    confidence: float
    explanations: List[RiskExplanationSchema] = []

    class Config:
        from_attributes = True

class AttackPathNodeSchema(BaseModel):
    path_node_id: str
    sequence_no: int
    entity_type: str
    entity_name: str
    relationship: str

    class Config:
        from_attributes = True

class AttackPathSchema(BaseModel):
    path_id: str
    path_probability: float
    impact_score: float
    path_length: int
    status: str
    nodes: List[AttackPathNodeSchema] = []

    class Config:
        from_attributes = True

class ResponseRecommendationSchema(BaseModel):
    recommendation_id: str
    priority: str
    action_type: str
    description: str
    automation_supported: bool
    status: str

    class Config:
        from_attributes = True

class IncidentDetailSchema(BaseModel):
    incident_id: str
    organization_id: str
    title: str
    category: str
    severity: str
    severity_score: float
    confidence_score: float
    blast_radius_score: float
    business_impact_score: float
    status: str
    assigned_to: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    assessments: List[RiskAssessmentSchema] = []
    attack_paths: List[AttackPathSchema] = []
    recommendations: List[ResponseRecommendationSchema] = []

    class Config:
        from_attributes = True

class AuditEventSchema(BaseModel):
    audit_id: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: str
    timestamp: datetime
    previous_event_hash: str
    event_hash: str

    class Config:
        from_attributes = True
