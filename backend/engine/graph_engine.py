import networkx as nx
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from backend.models import Asset, AssetDependency, Identity, IdentityAssetAccess, AssetVulnerability, Vulnerability

class GraphAttackEngine:
    """
    Dynamic Attack-Path & Blast-Radius Engine using NetworkX Graph Data Structure.
    Constructs graph directly from enterprise database records: Identity -> Access -> Asset -> Dependency -> Vulnerability.
    """

    def __init__(self):
        self.G = nx.DiGraph()

    def build_graph_from_db(self, db: Session = None):
        """Construct knowledge graph dynamically from DB entities."""
        if not db:
            return self.build_default_acme_graph()

        self.G.clear()

        # 1. Fetch & Add Identities
        identities = db.query(Identity).all()
        for ident in identities:
            node_id = f"id:{ident.identity_id}"
            self.G.add_node(
                node_id,
                label=f"{ident.department_name} ({ident.identity_type})",
                type="IDENTITY",
                criticality=ident.criticality,
                privilege=ident.privilege_level
            )

        # 2. Fetch & Add Assets
        assets = db.query(Asset).all()
        for ast in assets:
            node_id = f"ast:{ast.asset_id}"
            self.G.add_node(
                node_id,
                label=ast.name,
                type=ast.asset_type,
                criticality=ast.business_criticality,
                internet_exposed=ast.internet_exposed
            )

        # 3. Add Identity Asset Access Edges
        accesses = db.query(IdentityAssetAccess).all()
        for acc in accesses:
            src = f"id:{acc.identity_id}"
            tgt = f"ast:{acc.asset_id}"
            if self.G.has_node(src) and self.G.has_node(tgt):
                self.G.add_edge(src, tgt, relationship="ACCESSES", privilege=acc.privilege)

        # 4. Add Asset Dependency Edges
        deps = db.query(AssetDependency).all()
        for dep in deps:
            src = f"ast:{dep.source_asset_id}"
            tgt = f"ast:{dep.target_asset_id}"
            if self.G.has_node(src) and self.G.has_node(tgt):
                self.G.add_edge(src, tgt, relationship=dep.relationship_type, criticality=dep.criticality)

        # 5. Add Asset Vulnerability Nodes & Edges
        vulns = db.query(AssetVulnerability).all()
        for v in vulns:
            v_obj = db.query(Vulnerability).filter(Vulnerability.vulnerability_id == v.vulnerability_id).first()
            if v_obj:
                v_node = f"vuln:{v_obj.cve_id}"
                self.G.add_node(v_node, label=v_obj.cve_id, type="VULNERABILITY", criticality=9)
                tgt_ast = f"ast:{v.asset_id}"
                if self.G.has_node(tgt_ast):
                    self.G.add_edge(v_node, tgt_ast, relationship="EXPLOITS")

        if len(self.G.nodes) == 0:
            self.build_default_acme_graph()

    def build_default_acme_graph(self):
        """Construct fallback static graph representation for Acme FinTech Ltd."""
        self.G.clear()
        
        self.G.add_node("id:cfo", label="CFO Identity (cfo@acme.test)", type="IDENTITY", criticality=10)
        self.G.add_node("id:sales", label="Sales Employee (employee1@acme.test)", type="IDENTITY", criticality=4)
        self.G.add_node("id:dev", label="Lead Dev (dev.lead@acme.test)", type="IDENTITY", criticality=8)

        self.G.add_node("cred:cfo_pass", label="CFO Password Indicator", type="CREDENTIAL", sensitivity=9)
        self.G.add_node("cred:api_key", label="Payment API Key (WRITE)", type="API_KEY", sensitivity=10)

        self.G.add_node("ast-erp-01", label="ERP-01 Core System", type="APPLICATION", criticality=10)
        self.G.add_node("ast-vpn-01", label="VPN Gateway Server", type="SERVER", criticality=9)
        self.G.add_node("ast-gitlab-01", label="GitLab Repository", type="APPLICATION", criticality=8)

        self.G.add_node("ast-findb-01", label="FinanceDB Production Cluster", type="DATABASE", criticality=10)
        self.G.add_node("vendor:payroll", label="PayrollCo Vendor Integration", type="VENDOR", criticality=8)

        self.G.add_edge("id:cfo", "cred:cfo_pass", relationship="OWNS")
        self.G.add_edge("cred:cfo_pass", "ast-vpn-01", relationship="AUTHENTICATES")
        self.G.add_edge("ast-vpn-01", "ast-erp-01", relationship="ACCESSED_VIA")
        self.G.add_edge("ast-erp-01", "ast-findb-01", relationship="READ_WRITE")
        self.G.add_edge("ast-findb-01", "vendor:payroll", relationship="SYNC_DATA")

        self.G.add_edge("id:dev", "cred:api_key", relationship="OWNS")

    def calculate_blast_radius(self, start_node: str, db: Session = None) -> Dict[str, Any]:
        """Calculate reachable nodes and compute dynamic blast radius score."""
        if not self.G.has_node(start_node):
            self.build_graph_from_db(db)

        if not self.G.has_node(start_node):
            # Try finding node by label substring match
            found = False
            for node, data in self.G.nodes(data=True):
                if start_node.lower() in node.lower() or start_node.lower() in data.get("label", "").lower():
                    start_node = node
                    found = True
                    break
            if not found:
                start_node = list(self.G.nodes)[0] if self.G.nodes else "id:cfo"

        reachable = list(nx.descendants(self.G, start_node))
        reachable_nodes = [start_node] + reachable

        critical_services = []
        databases = []
        vendors = []
        total_criticality = 0.0

        for node in reachable_nodes:
            n_data = self.G.nodes.get(node, {})
            node_type = n_data.get("type", "UNKNOWN")
            crit = n_data.get("criticality", n_data.get("sensitivity", 5))
            total_criticality += crit

            label = n_data.get("label", node)
            if node_type in ["APPLICATION", "SERVER"]:
                critical_services.append(label)
            elif node_type == "DATABASE":
                databases.append(label)
            elif node_type == "VENDOR":
                vendors.append(label)

        blast_score = min(100.0, (len(reachable) * 15.0) + (total_criticality * 1.5))
        level = "CRITICAL" if blast_score >= 80 else ("HIGH" if blast_score >= 60 else ("MEDIUM" if blast_score >= 40 else "LOW"))

        return {
            "start_node": start_node,
            "direct_exposure_count": 1,
            "reachable_nodes_count": len(reachable),
            "reachable_critical_services": critical_services,
            "reachable_databases": databases,
            "reachable_vendors": vendors,
            "blast_radius_score": round(blast_score, 1),
            "blast_radius_level": level
        }

    def generate_attack_path(self, start_node: str, end_node: str = "ast-findb-01", db: Session = None) -> List[Dict[str, Any]]:
        """Generate shortest attack path sequence nodes from entry point to crown jewel asset."""
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
            shortest_path = nx.shortest_path(self.G, source=start_node, target=end_node)
        except Exception:
            shortest_path = [start_node, end_node]

        nodes = []
        for idx, node_id in enumerate(shortest_path):
            n_data = self.G.nodes.get(node_id, {})
            rel = "EXPLOITS" if idx == 0 else ("ACCESSES" if idx < len(shortest_path) - 1 else "READ_WRITE")
            nodes.append({
                "sequence_no": idx + 1,
                "entity_type": n_data.get("type", "ASSET"),
                "entity_name": n_data.get("label", node_id),
                "relationship": rel
            })
        return nodes

graph_engine = GraphAttackEngine()
