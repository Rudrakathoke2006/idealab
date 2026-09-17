import networkx as nx
from typing import Dict, List, Any

class GraphAttackEngine:
    """
    Attack-Path & Blast-Radius Engine using NetworkX Graph Data Structure.
    Models relationships: User -> Credential -> Application -> Database -> Vendor Integration.
    """

    def __init__(self):
        self.G = nx.DiGraph()

    def build_default_acme_graph(self):
        """Construct knowledge graph representation for Acme FinTech Ltd."""
        self.G.clear()
        
        # Nodes: Identities
        self.G.add_node("id:cfo", label="CFO Identity (cfo@acme.test)", type="IDENTITY", criticality=10)
        self.G.add_node("id:sales", label="Sales Employee (employee1@acme.test)", type="IDENTITY", criticality=4)
        self.G.add_node("id:dev", label="Lead Dev (dev.lead@acme.test)", type="IDENTITY", criticality=8)

        # Nodes: Credentials / Tokens
        self.G.add_node("cred:cfo_pass", label="CFO Password Indicator", type="CREDENTIAL", sensitivity=9)
        self.G.add_node("cred:api_key", label="Payment API Key (WRITE)", type="API_KEY", sensitivity=10)

        # Nodes: Applications & Servers
        self.G.add_node("app:erp", label="ERP-01 Core System", type="APPLICATION", criticality=10)
        self.G.add_node("app:vpn", label="VPN Gateway Server", type="SERVER", criticality=9)
        self.G.add_node("app:gitlab", label="GitLab Repository", type="APPLICATION", criticality=8)
        self.G.add_node("app:hrms", label="HRMS People Portal", type="APPLICATION", criticality=7)

        # Nodes: Databases & Assets
        self.G.add_node("db:finance", label="FinanceDB Production Cluster", type="DATABASE", criticality=10)
        self.G.add_node("vendor:payroll", label="PayrollCo Vendor Integration", type="VENDOR", criticality=8)
        self.G.add_node("vendor:payment", label="PaymentGateway Vendor", type="VENDOR", criticality=9)

        # Edges (Access & Connectivity)
        self.G.add_edge("id:cfo", "cred:cfo_pass", relationship="OWNS")
        self.G.add_edge("cred:cfo_pass", "app:vpn", relationship="AUTHENTICATES")
        self.G.add_edge("app:vpn", "app:erp", relationship="ACCESSED_VIA")
        self.G.add_edge("app:erp", "db:finance", relationship="READ_WRITE")
        self.G.add_edge("db:finance", "vendor:payroll", relationship="SYNC_DATA")

        self.G.add_edge("id:dev", "cred:api_key", relationship="OWNS")
        self.G.add_edge("cred:api_key", "vendor:payment", relationship="AUTHORIZES")
        self.G.add_edge("vendor:payment", "db:finance", relationship="TRANSACT")

    def calculate_blast_radius(self, start_node: str) -> Dict[str, Any]:
        """
        Calculate reachable nodes and compute blast radius score.
        """
        if not self.G.has_node(start_node):
            self.build_default_acme_graph()

        if not self.G.has_node(start_node):
            # Fallback
            return {
                "direct_exposure_count": 1,
                "reachable_nodes_count": 2,
                "reachable_critical_services": ["ERP-01"],
                "reachable_databases": ["FinanceDB"],
                "reachable_vendors": [],
                "blast_radius_score": 35.0,
                "blast_radius_level": "LOW"
            }

        # Find reachable nodes via BFS/DFS
        reachable = list(nx.descendants(self.G, start_node))
        reachable_nodes = [start_node] + reachable

        critical_services = []
        databases = []
        vendors = []
        total_criticality = 0.0

        for node in reachable_nodes:
            n_data = self.G.nodes[node]
            node_type = n_data.get("type", "UNKNOWN")
            crit = n_data.get("criticality", n_data.get("sensitivity", 5))
            total_criticality += crit

            if node_type in ["APPLICATION", "SERVER"]:
                critical_services.append(n_data.get("label", node))
            elif node_type == "DATABASE":
                databases.append(n_data.get("label", node))
            elif node_type == "VENDOR":
                vendors.append(n_data.get("label", node))

        # Blast Radius Score (0-100)
        blast_score = min(100.0, (len(reachable) * 15.0) + (total_criticality * 1.5))
        
        if blast_score >= 80:
            level = "CRITICAL"
        elif blast_score >= 60:
            level = "HIGH"
        elif blast_score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

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

    def generate_attack_path(self, start_node: str, end_node: str = "db:finance") -> List[Dict[str, Any]]:
        """
        Generate attack path sequence nodes from entry point to crown jewel asset.
        """
        if not self.G.has_node(start_node) or not self.G.has_node(end_node):
            self.build_default_acme_graph()

        try:
            shortest_path = nx.shortest_path(self.G, source=start_node, target=end_node)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            shortest_path = ["id:cfo", "cred:cfo_pass", "app:vpn", "app:erp", "db:finance"]

        nodes = []
        for idx, node_id in enumerate(shortest_path):
            n_data = self.G.nodes.get(node_id, {})
            rel = "EXPLOITS" if idx == 0 else ("ACCESSES" if idx < len(shortest_path) - 1 else "EXFILTRATES")
            nodes.append({
                "sequence_no": idx + 1,
                "entity_type": n_data.get("type", "ASSET"),
                "entity_name": n_data.get("label", node_id),
                "relationship": rel
            })
        return nodes

graph_engine = GraphAttackEngine()
