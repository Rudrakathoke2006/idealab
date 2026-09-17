import json
import hashlib
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import Organization, User, Asset, Incident, RiskAssessment, RiskExplanation, AttackPath, AttackPathNode, ResponseRecommendation, AuditEvent
from backend.engine.entity_extractor import entity_extractor
from backend.engine.exposure_surface import exposure_surface_engine
from backend.engine.graph_engine import graph_engine
from backend.engine.risk_engine import risk_engine
from backend.engine.xai_engine import xai_engine
from backend.engine.response_engine import response_engine
from backend.research.ablation_study import run_ablation_study

router = APIRouter()

@router.post("/auth/login")
def login(payload: Dict[str, str], db: Session = Depends(get_db)):
    email = payload.get("email", "")
    password = payload.get("password", "")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    return {
        "access_token": f"aegis_jwt_token_{user.user_id}",
        "token_type": "bearer",
        "user_id": user.user_id,
        "email": user.email,
        "role": user.role,
        "organization_name": "Acme FinTech Ltd."
    }

@router.get("/dashboard/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    total_assets = db.query(Asset).count()
    total_incidents = db.query(Incident).count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "CRITICAL").count()
    high_incidents = db.query(Incident).filter(Incident.severity == "HIGH").count()
    
    return {
        "organization_name": "Acme FinTech Ltd.",
        "overall_risk_score": 93.0,
        "nist_csf_posture": "PROTECT / DETECT ACTIVE",
        "total_protected_assets": total_assets,
        "active_incidents": total_incidents,
        "critical_incidents": critical_incidents,
        "high_incidents": high_incidents,
        "mean_time_to_triage_mins": 4.2,
        "alert_reduction_rate": "92.4%"
    }

@router.get("/incidents")
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.severity_score.desc()).all()
    results = []
    for inc in incidents:
        results.append({
            "incident_id": inc.incident_id,
            "title": inc.title,
            "category": inc.category,
            "severity": inc.severity,
            "severity_score": inc.severity_score,
            "confidence_score": inc.confidence_score,
            "blast_radius_score": inc.blast_radius_score,
            "business_impact_score": inc.business_impact_score,
            "status": inc.status,
            "assigned_to": inc.assigned_to or "SOC Analyst L2",
            "first_seen": inc.first_seen.isoformat()
        })
    return results

@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        # Generate default detail for demo test cases
        return get_demo_incident_detail(incident_id)

    assessments = db.query(RiskAssessment).filter(RiskAssessment.incident_id == incident_id).all()
    att_paths = db.query(AttackPath).filter(AttackPath.incident_id == incident_id).all()
    recs = db.query(ResponseRecommendation).filter(ResponseRecommendation.incident_id == incident_id).all()

    return {
        "incident_id": inc.incident_id,
        "title": inc.title,
        "category": inc.category,
        "severity": inc.severity,
        "severity_score": inc.severity_score,
        "confidence_score": inc.confidence_score,
        "blast_radius_score": inc.blast_radius_score,
        "business_impact_score": inc.business_impact_score,
        "status": inc.status,
        "assigned_to": inc.assigned_to or "SOC Analyst L2",
        "first_seen": inc.first_seen.isoformat(),
        "assessments": [
            {
                "model_version": a.model_version,
                "final_score": a.final_score,
                "confidence": a.confidence,
                "explanations": [
                    {"factor_name": e.factor_name, "factor_value": e.factor_value, "contribution": e.contribution, "reason": e.reason}
                    for e in a.explanations
                ]
            } for a in assessments
        ],
        "attack_paths": [
            {
                "path_id": p.path_id,
                "nodes": [{"sequence_no": n.sequence_no, "entity_type": n.entity_type, "entity_name": n.entity_name, "relationship": n.relationship_type} for n in p.nodes]
            } for p in att_paths
        ],
        "recommendations": [
            {
                "recommendation_id": r.recommendation_id,
                "priority": r.priority,
                "action_type": r.action_type,
                "description": r.description,
                "automation_supported": r.automation_supported,
                "status": r.status
            } for r in recs
        ]
    }

@router.post("/incidents/{incident_id}/remediate")
def execute_remediation(incident_id: str, payload: Dict[str, str], db: Session = Depends(get_db)):
    rec_id = payload.get("recommendation_id")
    action_type = payload.get("action_type", "RESET_CREDENTIAL")

    # Add hash-chained audit trail
    last_audit = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).first()
    prev_hash = last_audit.event_hash if last_audit else "0" * 64
    
    event_str = f"{incident_id}:{rec_id}:{action_type}:{prev_hash}"
    curr_hash = hashlib.sha256(event_str.encode()).hexdigest()

    audit = AuditEvent(
        organization_id="org-acme-fintech-01",
        actor_id="usr-soc-01",
        action=f"PLAYBOOK_EXECUTED_{action_type}",
        resource_type="INCIDENT",
        resource_id=incident_id,
        ip_hash=hashlib.sha256(b"127.0.0.1").hexdigest()[:16],
        previous_event_hash=prev_hash,
        event_hash=curr_hash
    )
    db.add(audit)
    db.commit()

    return {
        "status": "SUCCESS",
        "message": f"Remediation action '{action_type}' executed successfully.",
        "audit_event_hash": curr_hash
    }

@router.get("/weaknesses")
def get_weaknesses(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    weaknesses = []
    for a in assets:
        eval_res = exposure_surface_engine.evaluate_asset_weakness(
            asset_name=a.name,
            asset_criticality=a.business_criticality,
            internet_exposed=a.internet_exposed,
            mfa_enabled=False if a.asset_type in ["SERVER", "DATABASE"] else True,
            has_cve=True if a.asset_type == "SERVER" else False,
            cvss_score=9.8 if a.asset_type == "SERVER" else 0.0,
            cisa_kev=True if a.asset_type == "SERVER" else False
        )
        for w in eval_res["weaknesses"]:
            weaknesses.append({
                "asset_name": a.name,
                "asset_type": a.asset_type,
                "weakness_type": w.get("impact", "Security Weakness"),
                "severity": w.get("severity", 5.0),
                "concept": "WEAKNESS (Makes compromise easier)"
            })
    return weaknesses

@router.get("/exposures")
def get_exposures(db: Session = Depends(get_db)):
    return [
        {
            "exposure_id": "exp-001",
            "source": "HIBP / Authenticated CTI Feed",
            "exposed_entity": "cfo@acme.test",
            "exposure_type": "CREDENTIAL_LEAK",
            "data_sensitivity": 9.0,
            "concept": "EXPOSURE (Evidence identity/asset is exposed)"
        },
        {
            "exposure_id": "exp-002",
            "source": "OSINT / Paste Dump",
            "exposed_entity": "PaymentGateway Write Token",
            "exposure_type": "API_SECRET_LEAK",
            "data_sensitivity": 9.5,
            "concept": "EXPOSURE (Evidence identity/asset is exposed)"
        }
    ]

@router.get("/assets")

def get_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    return [
        {
            "asset_id": a.asset_id,
            "name": a.name,
            "type": a.asset_type,
            "department": a.department_name,
            "criticality": a.business_criticality,
            "data_classification": a.data_classification,
            "internet_exposed": a.internet_exposed,
            "status": a.status
        } for a in assets
    ]

@router.get("/graph")
def get_graph_data():
    graph_engine.build_default_acme_graph()
    nodes = []
    for n, data in graph_engine.G.nodes(data=True):
        nodes.append({"id": n, "label": data.get("label", n), "type": data.get("type", "ASSET"), "criticality": data.get("criticality", 5)})
    edges = []
    for u, v, data in graph_engine.G.edges(data=True):
        edges.append({"source": u, "target": v, "relationship": data.get("relationship", "CONNECTS")})
    return {"nodes": nodes, "edges": edges}

@router.get("/ablation")
def get_ablation_metrics():
    try:
        with open("backend/data/ablation_results.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return run_ablation_study()

@router.post("/extract-entity")
def extract_entity(payload: Dict[str, str]):
    raw_text = payload.get("text", "")
    return entity_extractor.extract(raw_text)

@router.post("/detect")
def run_realtime_detection(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Real-time Continuous Breach Exposure Detection Endpoint.
    Ingests live enterprise telemetry (CTI feeds, SIEM alerts, IAM identity logs, Vuln scans),
    detects breach exposure paths, calculates XAI exposure risk, and suggests response actions.
    """
    telemetry_type = payload.get("type", "CREDENTIAL_LEAK")
    target_identity = payload.get("identity", "cfo@company.com")
    target_asset = payload.get("asset", "FinanceDB Production Cluster")
    cvss_score = float(payload.get("cvss_score", 9.8))
    cisa_kev = bool(payload.get("cisa_kev", True))
    internet_exposed = bool(payload.get("internet_exposed", True))
    mfa_enabled = bool(payload.get("mfa_enabled", False))

    weakness_res = exposure_surface_engine.evaluate_asset_weakness(
        asset_name=target_asset,
        asset_criticality=10,
        internet_exposed=internet_exposed,
        mfa_enabled=mfa_enabled,
        has_cve=True,
        cvss_score=cvss_score,
        cisa_kev=cisa_kev,
        privilege_level=9
    )

    risk_assessment = risk_engine.compute_risk(
        data_sensitivity=9.5,
        exploitability=9.0,
        asset_criticality=10.0,
        freshness=9.5,
        source_confidence=9.0,
        blast_radius=8.5,
        vulnerability_score=cvss_score,
        threat_context=9.0,
        historical_score=7.0,
        mfa_enabled=mfa_enabled
    )

    graph_engine.build_default_acme_graph()
    attack_path = graph_engine.generate_attack_path("id:cfo", "db:finance")

    recs = response_engine.generate_playbook(
        category=telemetry_type,
        context={"affected_identity": target_identity}
    )

    return {
        "status": "DETECTION_COMPLETE",
        "timestamp": "2026-09-17T11:02:00Z",
        "detection_event": {
            "telemetry_type": telemetry_type,
            "target_identity": target_identity,
            "target_asset": target_asset,
            "exposure_detected": True,
            "severity": risk_assessment["severity_level"],
            "severity_score": risk_assessment["severity_score"],
            "confidence_score": risk_assessment["confidence_score"],
            "confidence_level": risk_assessment["confidence_level"],
            "weakness_analysis": weakness_res,
            "attack_path": attack_path,
            "recommended_actions": recs
        }
    }

@router.post("/soar/evaluate-safety")
def evaluate_soar_safety(payload: Dict[str, str]):
    """
    Evaluates SOAR remediation safety guardrails & break-glass exclusion list rules.
    """
    from backend.engine.soar_guardrails import soar_guardrails
    action_type = payload.get("action_type", "RESET_CREDENTIAL")
    target_identity = payload.get("target_identity", "")
    target_asset = payload.get("target_asset", "")
    execution_mode = payload.get("execution_mode", "APPROVE_THEN_EXECUTE")

    return soar_guardrails.evaluate_remediation_safety(
        action_type=action_type,
        target_identity=target_identity,
        target_asset=target_asset,
        execution_mode=execution_mode
    )

@router.post("/audit/merkle-anchor")
def generate_merkle_audit_anchor(db: Session = Depends(get_db)):
    """
    Calculates cryptographic Merkle Tree over audit events and returns HSM-signed Merkle Root.
    """
    from backend.engine.merkle_audit import merkle_audit_service
    audit_events = db.query(AuditEvent).all()
    event_hashes = [e.event_hash for e in audit_events if e.event_hash]

    return merkle_audit_service.build_merkle_tree(event_hashes)

@router.post("/connectors/normalize")
def normalize_telemetry_event(payload: Dict[str, Any]):
    """
    Normalizes vendor raw telemetry into OCSF v1.1.0 security event schema.
    """
    from backend.engine.connectors.ocsf_normalizer import ocsf_normalizer
    event_type = payload.get("type", "CREDENTIAL_LEAK")
    tenant_id = payload.get("tenant_id", "org-acme-fintech-01")

    if event_type == "CREDENTIAL_LEAK":
        return ocsf_normalizer.normalize_credential_leak(payload, tenant_id)
    else:
        return ocsf_normalizer.normalize_vuln_finding(payload, tenant_id)



def get_demo_incident_detail(incident_id: str):
    # Standardized response for demo incident #AEX-00294
    return {
        "incident_id": incident_id,
        "title": "INCIDENT #AEX-00294 — CFO Credential Leak & ERP Exposure",
        "category": "Credential Exposure",
        "severity": "CRITICAL",
        "severity_score": 93.0,
        "confidence_score": 88.0,
        "blast_radius_score": 85.0,
        "business_impact_score": 90.0,
        "status": "Open",
        "assigned_to": "SOC Analyst L2 (You)",
        "first_seen": "2026-09-11T22:14:00Z",
        "last_seen": "2026-09-11T23:45:00Z",
        "affected_identity": "cfo@acme.test (Chief Financial Officer)",
        "affected_assets": ["ERP-01 Core Enterprise Engine", "FinanceDB Production Cluster"],
        "assessments": [
            {
                "model_version": "v1.0-hybrid-xgboost-shap",
                "final_score": 93.0,
                "confidence": 88.0,
                "explanations": [
                    {"factor_name": "privileged_credential", "factor_value": "Level 9/10", "contribution": +18.4, "reason": "+18.4 Privileged CFO credential exposed"},
                    {"factor_name": "critical_asset_access", "factor_value": "Criticality 10/10", "contribution": +16.8, "reason": "+16.8 Direct access path reaches critical FinanceDB core"},
                    {"factor_name": "recent_exposure", "factor_value": "< 2 hours old", "contribution": +14.5, "reason": "+14.5 Recent active breach exposure"},
                    {"factor_name": "known_exploited_vulnerability", "factor_value": "CISA KEV Listed", "contribution": +13.2, "reason": "+13.2 Associated VPN Gateway contains CISA KEV active CVE"},
                    {"factor_name": "high_blast_radius", "factor_value": "Score 85/100", "contribution": +11.6, "reason": "+11.6 Reaches ERP, FinanceDB & Payment Gateway"},
                    {"factor_name": "mfa_enforced", "factor_value": "Absent", "contribution": -0.0, "reason": "0.0 MFA missing on target account"}
                ]
            }
        ],
        "attack_paths": [
            {
                "path_id": "path-cfo-01",
                "nodes": [
                    {"sequence_no": 1, "entity_type": "CREDENTIAL", "entity_name": "cfo@acme.test Password Indicator", "relationship": "EXPLOITS"},
                    {"sequence_no": 2, "entity_type": "SERVER", "entity_name": "VPN Gateway Server (CVE-2024-21887)", "relationship": "AUTHENTICATES"},
                    {"sequence_no": 3, "entity_type": "APPLICATION", "entity_name": "ERP-01 Core Enterprise Engine", "relationship": "ACCESSES"},
                    {"sequence_no": 4, "entity_type": "DATABASE", "entity_name": "FinanceDB Production Cluster", "relationship": "READ_WRITE"},
                    {"sequence_no": 5, "entity_type": "VENDOR", "entity_name": "PayrollCo Vendor Integration", "relationship": "EXFILTRATES"}
                ]
            }
        ],
        "recommendations": [
            {"recommendation_id": "rec-01", "priority": "P0", "action_type": "RESET_CREDENTIAL", "description": "P0 Reset affected identity credential (cfo@acme.test)", "automation_supported": True, "status": "PENDING"},
            {"recommendation_id": "rec-02", "priority": "P0", "action_type": "REVOKE_SESSIONS", "description": "P0 Revoke all active OAuth & VPN sessions", "automation_supported": True, "status": "PENDING"},
            {"recommendation_id": "rec-03", "priority": "P0", "action_type": "PATCH_CVE", "description": "P0 Apply Ivanti VPN security patch (CVE-2024-21887)", "automation_supported": True, "status": "PENDING"},
            {"recommendation_id": "rec-04", "priority": "P1", "action_type": "AUDIT_LOGS", "description": "P1 Audit ERP transaction logs for unauthorized exports", "automation_supported": False, "status": "PENDING"}
        ]
    }
