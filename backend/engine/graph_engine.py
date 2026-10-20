"""
AEGIS-X Directed Multi-Attribute Probabilistic Graph Engine (Dossier B2, Section 5.2)

Formal Graph Formulation:
  Graph G = (N, E), where N = identities ∪ assets ∪ services.
  Each edge e = (u, v) carries a traversal probability p_e in (0.0, 1.0] derived from
  privilege level, protocol security, and MFA enforcement.

Most-Probable-Path Reachability:
  For identity i and crown jewel c:
    r(i, c) = max_{pi: i -> c} prod_{e in pi} p_e
  Computed exactly via Dijkstra using non-negative additive edge weight w_e = -ln(p_e).
  Because distance d = sum -ln(p_e) = -ln(prod p_e), the shortest path distance yields:
    r(i, c) = exp(-d(i, c))

Impact Metric:
  I(i) = sum_c (w_c * r(i, c)) / sum_c (w_c) in [0.0, 1.0]
  Blast Score = I(i) * 100.0 in [0.0, 100.0]

Reverse Dependency:
  Dep(i) = { a in Assets | exists path a -> i or i is critical dependency of a }
"""

import math
import numpy as np
import networkx as nx
from typing import Dict, List, Any, Tuple, Optional, Set
from sqlalchemy.orm import Session
from backend.engine.config import default_engine_config

class GraphAttackEngine:
    """
    Research-Grade Probabilistic Graph Engine for Exposure Triage and Response Safety.
    """

    def __init__(self, config=None):
        self.config = config or default_engine_config
        self.G = nx.DiGraph()
        self._cache: Dict[str, Any] = {}

    def add_probabilistic_edge(
        self,
        src: str,
        tgt: str,
        relationship: str = "ACCESSES",
        privilege: str = "USER",
        mfa_protected: bool = False,
        protocol: str = "HTTPS",
        base_prob: Optional[float] = None,
        criticality: float = 5.0
    ):
        """
        Adds directed edge with mathematically bounded traversal probability p_e in (0, 1]
        and Dijkstra weight w_e = -ln(p_e).
        """
        if base_prob is not None:
            p = max(1e-4, min(1.0, float(base_prob)))
        else:
            # Derive probability from privilege, MFA, and protocol
            if privilege in ["SUPER_ADMIN", "DOMAIN_ADMIN", "ROOT"]:
                p_priv = 0.95
            elif privilege in ["ADMIN", "ELEVATED"]:
                p_priv = 0.80
            elif privilege in ["SERVICE_PRINCIPAL", "API"]:
                p_priv = 0.75
            else:
                p_priv = 0.50

            mfa_mult = 0.35 if mfa_protected else 1.0
            proto_mult = 0.90 if protocol in ["SSH", "RDP"] else 0.70

            p = max(0.01, min(0.99, p_priv * mfa_mult * proto_mult))

        # Weight for Dijkstra: w = -ln(p), strictly positive since p <= 1.0
        w = -math.log(p)

        self.G.add_edge(
            src, tgt,
            relationship=relationship,
            privilege=privilege,
            mfa_protected=mfa_protected,
            protocol=protocol,
            probability=p,
            weight=w,
            criticality=criticality
        )

    def build_default_enterprise_graph(self):
        """
        Construct reference enterprise multi-attribute graph with realistic cyclic topologies,
        admin infrastructure, identity providers, and crown-jewel assets.
        """
        self.G.clear()
        self._cache.clear()

        # 1. Identities (with privilege and business weights)
        self.G.add_node("id:cfo", label="Chief Financial Officer", type="IDENTITY", criticality=10, privilege=9, is_crown_jewel=True, is_admin=False, business_weight=5.0)
        self.G.add_node("id:domain_admin", label="Primary Enterprise Admin", type="IDENTITY", criticality=10, privilege=10, is_crown_jewel=True, is_admin=True, business_weight=4.0)
        self.G.add_node("id:dev", label="Platform Lead Engineer", type="IDENTITY", criticality=8, privilege=8, is_crown_jewel=False, is_admin=False, business_weight=3.0)
        self.G.add_node("id:sales", label="Sales Representative", type="IDENTITY", criticality=4, privilege=3, is_crown_jewel=False, is_admin=False, business_weight=1.0)
        self.G.add_node("id:svc_backup", label="Enterprise Backup Service Principal", type="SERVICE_ACCOUNT", criticality=9, privilege=8, is_crown_jewel=False, is_admin=False, business_weight=3.0)

        # 2. Authentication & Infrastructure Nodes (T0 members)
        self.G.add_node("ast-dc-01", label="Domain Controller Primary (DC01)", type="DOMAIN_CONTROLLER", criticality=10, internet_exposed=False, is_crown_jewel=True, is_idp=True)
        self.G.add_node("ast-idp-01", label="Core Okta/Entra Identity Provider", type="IDP", criticality=10, internet_exposed=False, is_crown_jewel=True, is_idp=True)
        self.G.add_node("ast-vpn-01", label="Corporate VPN Gateway", type="SERVER", criticality=9, internet_exposed=True, is_crown_jewel=False)

        # 3. Enterprise Applications & Crown Jewel Databases
        self.G.add_node("ast-findb-01", label="FinanceDB Production Cluster", type="DATABASE", criticality=10, internet_exposed=False, is_crown_jewel=True)
        self.G.add_node("ast-erp-01", label="ERP Core Application", type="APPLICATION", criticality=10, internet_exposed=False, is_crown_jewel=True)

        self.G.add_node("ast-gitlab-01", label="GitLab Source Code Platform", type="APPLICATION", criticality=8, internet_exposed=False, is_crown_jewel=False)

        self.G.add_node("vendor:payroll", label="External Payroll Integration API", type="VENDOR", criticality=7, internet_exposed=True, is_crown_jewel=False)

        # 4. Credentials & Token Connectors
        self.G.add_node("cred:cfo_pass", label="CFO Credential Indicator", type="CREDENTIAL", criticality=9, is_crown_jewel=False)
        self.G.add_node("cred:api_key", label="Payment Write API Key", type="API_KEY", criticality=10, is_crown_jewel=True)

        # 5. Probabilistic Directed Edges
        self.add_probabilistic_edge("id:domain_admin", "ast-dc-01", relationship="ADMINISTERS", privilege="SUPER_ADMIN", base_prob=0.98)
        self.add_probabilistic_edge("id:domain_admin", "ast-idp-01", relationship="ADMINISTERS", privilege="SUPER_ADMIN", base_prob=0.98)
        self.add_probabilistic_edge("ast-dc-01", "ast-findb-01", relationship="KERBEROS_AUTH", privilege="ADMIN", base_prob=0.90)

        self.add_probabilistic_edge("id:cfo", "cred:cfo_pass", relationship="OWNS", base_prob=1.0)
        self.add_probabilistic_edge("cred:cfo_pass", "ast-vpn-01", relationship="AUTHENTICATES", privilege="USER", mfa_protected=False, base_prob=0.95)
        self.add_probabilistic_edge("ast-vpn-01", "ast-erp-01", relationship="ACCESSES", privilege="USER", base_prob=0.85)
        self.add_probabilistic_edge("ast-erp-01", "ast-findb-01", relationship="READ_WRITE", privilege="ADMIN", base_prob=0.90)
        self.add_probabilistic_edge("ast-findb-01", "vendor:payroll", relationship="SYNC_DATA", base_prob=0.70)
        # Cyclic feedback loop
        self.add_probabilistic_edge("vendor:payroll", "ast-vpn-01", relationship="CALLBACK_API", base_prob=0.50)

        self.add_probabilistic_edge("id:dev", "cred:api_key", relationship="OWNS", base_prob=1.0)
        self.add_probabilistic_edge("cred:api_key", "ast-findb-01", relationship="API_WRITE", base_prob=0.95)

        # Backup service account connects to all databases
        self.add_probabilistic_edge("id:svc_backup", "ast-findb-01", relationship="AUTOMATED_BACKUP", privilege="SERVICE_PRINCIPAL", base_prob=0.92)
        self.add_probabilistic_edge("id:svc_backup", "ast-erp-01", relationship="AUTOMATED_BACKUP", privilege="SERVICE_PRINCIPAL", base_prob=0.90)

    def build_graph_from_db(self, db: Session = None):
        """Construct knowledge graph dynamically from relational database entities."""
        if not db:
            return self.build_default_enterprise_graph()

        self.G.clear()
        self._cache.clear()

        try:
            from backend.models import Asset, AssetDependency, Identity, IdentityAssetAccess, AssetVulnerability, Vulnerability

            # 1. Identities
            identities = db.query(Identity).all()
            for ident in identities:
                node_id = f"id:{ident.identity_id}"
                is_admin = (ident.privilege_level >= 9 or "admin" in str(ident.department_name).lower())
                self.G.add_node(
                    node_id,
                    label=f"{ident.department_name} ({ident.identity_type})",
                    type="IDENTITY",
                    criticality=ident.criticality,
                    privilege=ident.privilege_level,
                    is_crown_jewel=(ident.privilege_level >= 9),
                    is_admin=is_admin,
                    business_weight=5.0 if is_admin else 1.0
                )

            # 2. Assets
            assets = db.query(Asset).all()
            for ast in assets:
                node_id = f"ast:{ast.asset_id}"
                is_jewel = (ast.business_criticality >= 9 or str(ast.asset_type).upper() in ["DATABASE", "ERP", "IDP", "DOMAIN_CONTROLLER"])
                is_idp = str(ast.asset_type).upper() in ["IDP", "DOMAIN_CONTROLLER", "KEY_MANAGEMENT"]
                self.G.add_node(
                    node_id,
                    label=ast.name,
                    type=ast.asset_type,
                    criticality=ast.business_criticality,
                    internet_exposed=ast.internet_exposed,
                    is_crown_jewel=is_jewel,
                    is_idp=is_idp
                )

            # 3. Access Edges
            accesses = db.query(IdentityAssetAccess).all()
            for acc in accesses:
                src = f"id:{acc.identity_id}"
                tgt = f"ast:{acc.asset_id}"
                if self.G.has_node(src) and self.G.has_node(tgt):
                    prob = 0.95 if acc.privilege in ["SUPER_ADMIN", "ADMIN"] else 0.60
                    self.add_probabilistic_edge(src, tgt, relationship="ACCESSES", privilege=acc.privilege, base_prob=prob)

            # 4. Asset Dependencies
            deps = db.query(AssetDependency).all()
            for dep in deps:
                src = f"ast:{dep.source_asset_id}"
                tgt = f"ast:{dep.target_asset_id}"
                if self.G.has_node(src) and self.G.has_node(tgt):
                    self.add_probabilistic_edge(src, tgt, relationship=dep.relationship_type, criticality=dep.criticality, base_prob=0.85)

            # 5. Vulnerabilities
            vulns = db.query(AssetVulnerability).all()
            for v in vulns:
                v_obj = db.query(Vulnerability).filter(Vulnerability.vulnerability_id == v.vulnerability_id).first()
                if v_obj:
                    v_node = f"vuln:{v_obj.cve_id}"
                    self.G.add_node(v_node, label=v_obj.cve_id, type="VULNERABILITY", criticality=9, is_crown_jewel=False)
                    tgt_ast = f"ast:{v.asset_id}"
                    if self.G.has_node(tgt_ast):
                        self.add_probabilistic_edge(v_node, tgt_ast, relationship="EXPLOITS", base_prob=0.90)

        except Exception:
            self.build_default_enterprise_graph()

        if len(self.G.nodes) == 0:
            self.build_default_enterprise_graph()

    def get_crown_jewel_nodes(self) -> List[Tuple[str, float]]:
        """Returns list of (node_id, weight) for all designated crown-jewel target assets."""
        jewels = []
        for n, data in self.G.nodes(data=True):
            is_target_type = data.get("type") in ["APPLICATION", "DATABASE", "SERVER", "DOMAIN_CONTROLLER", "IDP", "CLOUD_RESOURCE"]
            if is_target_type and (data.get("is_crown_jewel", False) or data.get("criticality", 0) >= 10):
                w = float(data.get("criticality", 10.0))
                jewels.append((n, w))
        if not jewels:
            for n, data in self.G.nodes(data=True):
                if data.get("type") in ["APPLICATION", "DATABASE", "SERVER"] and data.get("criticality", 0) >= 8:
                    jewels.append((n, float(data.get("criticality", 8.0))))
        return jewels


    def compute_most_probable_path_reach(self, source_node: str, target_node: str) -> float:
        """
        Calculates r(source, target) = max_{pi} prod p_e = exp(-d_Dijkstra).
        Returns 0.0 if unreachable.
        """
        if not self.G.has_node(source_node) or not self.G.has_node(target_node):
            return 0.0
        if source_node == target_node:
            return 1.0

        try:
            # Explicit Dijkstra with weight='weight' where weight = -ln(p_e)
            dist = nx.shortest_path_length(self.G, source=source_node, target=target_node, weight="weight")
            # r = exp(-dist)
            reach_prob = math.exp(-dist)
            return max(0.0, min(1.0, float(reach_prob)))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return 0.0

    def compute_impact(self, identity_node: str) -> Tuple[float, Dict[str, float]]:
        """
        Computes formal Impact metric (Dossier Equation 3):
          I(i) = sum_c (w_c * r(i, c)) / sum_c (w_c) in [0.0, 1.0]
        """
        if not self.G.has_node(identity_node):
            # Attempt fuzzy resolution
            for n in self.G.nodes:
                if identity_node.lower() in n.lower():
                    identity_node = n
                    break

        if not self.G.has_node(identity_node):
            return 0.0, {}

        crown_jewels = self.get_crown_jewel_nodes()
        if not crown_jewels:
            return 0.0, {}

        sum_weighted_reach = 0.0
        sum_weights = 0.0
        jewel_reaches = {}

        for c_node, w_c in crown_jewels:
            r_ic = self.compute_most_probable_path_reach(identity_node, c_node)
            jewel_reaches[c_node] = r_ic
            sum_weighted_reach += w_c * r_ic
            sum_weights += w_c

        impact = sum_weighted_reach / max(1e-6, sum_weights)
        return float(impact), jewel_reaches

    def compute_reverse_dependencies(self, identity_node: str) -> Set[str]:
        """
        Computes Dep(i): set of assets and services that depend on identity i
        via reverse reachability in the enterprise graph.
        """
        if not self.G.has_node(identity_node):
            for n in self.G.nodes:
                if identity_node.lower() in n.lower():
                    identity_node = n
                    break
        if not self.G.has_node(identity_node):
            return set()

        # Invert graph edges to find reverse reachable ancestors
        G_rev = self.G.reverse(copy=False)
        try:
            dep_nodes = set(nx.descendants(G_rev, identity_node))
        except Exception:
            dep_nodes = set()

        # Filter to assets and services only
        assets = {
            n for n in dep_nodes
            if self.G.nodes[n].get("type") in ["APPLICATION", "DATABASE", "SERVER", "SERVICE_ACCOUNT"]
        }
        return assets

    def derive_protected_set_t0(self) -> Set[str]:
        """
        Derives Protected Set T0 from attributes and graph position (Dossier Section 5.6):
          1. Members of IdP / Domain administrator groups or privilege >= 9.
          2. Nodes with active paths to or from Domain Controllers and IdP nodes.
          3. Entities tagged as crown jewel.
        """
        t0 = set()

        # 1. Attribute-based admin roles and crown jewels
        for n, data in self.G.nodes(data=True):
            if data.get("is_admin", False) or data.get("privilege", 0) >= 9:
                t0.add(n)
            if data.get("is_crown_jewel", False):
                t0.add(n)
            if data.get("is_idp", False) or data.get("type") in ["IDP", "DOMAIN_CONTROLLER", "KMS"]:
                t0.add(n)

        # 2. Graph-position: nodes with direct or 1-hop reach to core infrastructure
        core_nodes = [n for n, d in self.G.nodes(data=True) if d.get("is_idp", False) or d.get("type") in ["IDP", "DOMAIN_CONTROLLER"]]
        for core in core_nodes:
            # Predecessors of core nodes
            for pred in self.G.predecessors(core):
                t0.add(pred)
            # Successors of core nodes
            for succ in self.G.successors(core):
                t0.add(succ)

        return t0

    def calculate_blast_radius(self, start_node: str, db: Session = None) -> Dict[str, Any]:
        """
        Calculates blast radius score in [0.0, 100.0] using formal most-probable-path reach impact.
        Provides both the new non-saturating metric and the legacy reachable-node count baseline.
        """
        if not self.G.has_node(start_node):
            self.build_graph_from_db(db)

        if not self.G.has_node(start_node):
            for n in self.G.nodes:
                if start_node.lower() in n.lower():
                    start_node = n
                    break
        if not self.G.has_node(start_node):
            start_node = list(self.G.nodes)[0] if self.G.nodes else "id:cfo"

        # 1. New Formal Most-Probable-Path Impact Metric
        impact, jewel_reaches = self.compute_impact(start_node)
        blast_score = round(impact * 100.0, 1)

        # Reachable descendants
        try:
            reachable = list(nx.descendants(self.G, start_node))
        except Exception:
            reachable = []

        reachable_nodes = [start_node] + reachable

        # Identified critical services and jewels
        critical_services = [self.G.nodes[n].get("label", n) for n in reachable_nodes if self.G.nodes[n].get("type") in ["APPLICATION", "SERVER"]]
        databases = [self.G.nodes[n].get("label", n) for n in reachable_nodes if self.G.nodes[n].get("type") == "DATABASE"]
        crown_jewels = [self.G.nodes[n].get("label", n) for n in reachable_nodes if self.G.nodes[n].get("is_crown_jewel", False)]

        # If designated crown jewels are reached with high probability, floor at 75.0 (Critical Tier)
        max_reach = max(jewel_reaches.values()) if jewel_reaches else 0.0
        if len(crown_jewels) > 0 and max_reach >= 0.50:
            blast_score = max(75.0, blast_score)

        # Baseline: legacy reachable-node count formula for ablation comparison (Dossier Table IV)
        legacy_baseline_score = min(100.0, max(5.0, 15.0 * len(reachable) + 1.5 * sum(self.G.nodes[n].get("criticality", 5) for n in reachable_nodes)))


        # Categorical band
        if blast_score >= 80.0:
            level = "CRITICAL"
        elif blast_score >= 60.0:
            level = "HIGH"
        elif blast_score >= 40.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        deps = self.compute_reverse_dependencies(start_node)

        return {
            "start_node": start_node,
            "blast_radius_score": blast_score,
            "blast_radius_level": level,
            "impact_metric": round(impact, 4),
            "jewel_reaches": {k: round(v, 4) for k, v in jewel_reaches.items()},
            "reachable_nodes_count": len(reachable),
            "reachable_critical_services": critical_services,
            "reachable_databases": databases,
            "reachable_crown_jewels": crown_jewels,
            "reverse_dependent_assets": list(deps),
            "reverse_dependent_count": len(deps),
            "legacy_baseline_blast_score": round(legacy_baseline_score, 1),
            "contains_cycle": not nx.is_directed_acyclic_graph(self.G)
        }

    def generate_attack_path(self, start_node: str, end_node: str = "ast-findb-01", db: Session = None) -> List[Dict[str, Any]]:
        """
        Computes optimal attack path sequence using Dijkstra with edge weight -ln(p_e).
        """
        if not self.G.has_node(start_node) or not self.G.has_node(end_node):
            self.build_graph_from_db(db)

        if not self.G.has_node(start_node):
            for n in self.G.nodes:
                if "cfo" in n.lower() or "id:" in n.lower():
                    start_node = n
                    break
        if not self.G.has_node(end_node):
            for n in self.G.nodes:
                if "findb" in n.lower() or "db:" in n.lower():
                    end_node = n
                    break

        try:
            shortest_path = nx.shortest_path(self.G, source=start_node, target=end_node, weight="weight")
        except Exception:
            shortest_path = [start_node, end_node]

        nodes = []
        for idx, node_id in enumerate(shortest_path):
            n_data = self.G.nodes.get(node_id, {})
            rel = "ENTRY_POINT" if idx == 0 else ("ACCESSES" if idx < len(shortest_path) - 1 else "TARGET_CORE")
            nodes.append({
                "sequence_no": idx + 1,
                "entity_type": n_data.get("type", "ASSET"),
                "entity_name": n_data.get("label", node_id),
                "relationship": rel,
                "criticality": n_data.get("criticality", 5)
            })
        return nodes

    def analyze_choke_points(self, start_node: str, crown_jewel_target: str = "ast-findb-01") -> Dict[str, Any]:
        """Choke-point defense analysis: identifies single edge severance that maximally eliminates lateral attack paths."""
        if not self.G.has_node(start_node) or not self.G.has_node(crown_jewel_target):
            self.build_default_enterprise_graph()

        try:
            all_simple_paths = list(nx.all_simple_paths(self.G, start_node, crown_jewel_target, cutoff=6))
        except Exception:
            all_simple_paths = []

        if not all_simple_paths:
            return {"choke_point_identified": False, "recommended_cut_edge": None, "paths_eliminated": 0}

        edge_freq: Dict[Tuple[str, str], int] = {}
        for path in all_simple_paths:
            for i in range(len(path) - 1):
                edge = (path[i], path[i + 1])
                edge_freq[edge] = edge_freq.get(edge, 0) + 1

        best_edge = max(edge_freq.items(), key=lambda x: x[1])
        u, v = best_edge[0]

        return {
            "choke_point_identified": True,
            "recommended_cut_edge": {
                "source": u,
                "source_label": self.G.nodes[u].get("label", u),
                "target": v,
                "target_label": self.G.nodes[v].get("label", v),
                "relationship": self.G.edges[u, v].get("relationship", "CONNECTS")
            },
            "total_attack_paths": len(all_simple_paths),
            "paths_eliminated_by_cut": best_edge[1],
            "choke_point_efficiency_pct": round((best_edge[1] / max(1, len(all_simple_paths))) * 100.0, 1)
        }

graph_engine = GraphAttackEngine()
