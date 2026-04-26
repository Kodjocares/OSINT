"""
modules/graph_viz.py — Entity relationship graph builder and visualizer
Build link graphs connecting emails, domains, IPs, persons, accounts
Export to interactive HTML (pyvis) or GraphML (NetworkX)
"""

import json
import os
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class GraphViz:
    """Build and visualize OSINT entity relationship graphs."""

    NODE_COLORS = {
        "email":    "#00d4ff",
        "domain":   "#ff6b35",
        "ip":       "#3fb950",
        "username": "#a371f7",
        "phone":    "#e3b341",
        "person":   "#f85149",
        "company":  "#ffa657",
        "breach":   "#ff4444",
        "hash":     "#888888",
        "url":      "#66b2ff",
        "crypto":   "#f0b429",
        "default":  "#c9d1d9",
    }

    def __init__(self):
        self.nodes: Dict[str, Dict] = {}   # id -> {label, type, data}
        self.edges: List[Dict] = []        # [{from, to, label, weight}]

    # ──────────────────────────────────────────────────────────
    # NODE / EDGE MANAGEMENT
    # ──────────────────────────────────────────────────────────
    def add_node(self, node_id: str, label: str, node_type: str = "default",
                 data: Dict = None) -> str:
        """Add a node to the graph. Returns node_id."""
        nid = node_id.strip().lower()
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id":    nid,
                "label": label,
                "type":  node_type,
                "color": self.NODE_COLORS.get(node_type, self.NODE_COLORS["default"]),
                "data":  data or {},
                "size":  20,
            }
        return nid

    def add_edge(self, from_id: str, to_id: str, label: str = "",
                 weight: float = 1.0, evidence: str = "") -> None:
        """Add a directed edge between two nodes."""
        fid = from_id.strip().lower()
        tid = to_id.strip().lower()
        # Avoid duplicate edges
        existing = [(e["from"] == fid and e["to"] == tid) for e in self.edges]
        if not any(existing):
            self.edges.append({
                "from":     fid,
                "to":       tid,
                "label":    label,
                "weight":   weight,
                "evidence": evidence,
            })

    def add_connection(self, entity1_id: str, entity1_label: str, entity1_type: str,
                       entity2_id: str, entity2_label: str, entity2_type: str,
                       relationship: str, evidence: str = "") -> None:
        """Convenience: add both nodes and the connecting edge at once."""
        self.add_node(entity1_id, entity1_label, entity1_type)
        self.add_node(entity2_id, entity2_label, entity2_type)
        self.add_edge(entity1_id, entity2_id, relationship, evidence=evidence)

    # ──────────────────────────────────────────────────────────
    # AUTO-BUILD FROM OSINT DATA
    # ──────────────────────────────────────────────────────────
    def build_from_osint(self, target: str, osint_data: Dict) -> None:
        """
        Automatically extract entities and relationships from OSINT module output.
        Supports outputs from: breach_check, domain_intel, username_lookup,
        social_media, crypto_tracer, phone_lookup, email_header.
        """
        # Root target node
        target_type = self._guess_type(target)
        self.add_node(target, target, target_type)

        # ── From breach data ──────────────────────────
        breach = osint_data.get("breach_check", {}).get("data", {}).get("data", {})
        for b in breach.get("breaches", []):
            bname = b.get("name", "")
            if bname:
                self.add_connection(
                    target, target, "email",
                    f"breach:{bname}", bname, "breach",
                    "exposed_in", f"Found in {bname} breach"
                )

        # ── From domain intel ─────────────────────────
        domain_data = osint_data.get("domain_intel", {}).get("data", {})
        whois = domain_data.get("whois", {})
        if whois.get("registrar"):
            reg_id = f"registrar:{whois['registrar']}"
            self.add_connection(target, target, "domain",
                                reg_id, whois["registrar"], "company",
                                "registered_with")
        if whois.get("emails"):
            emails = whois["emails"]
            if isinstance(emails, str):
                emails = [emails]
            for em in (emails or []):
                self.add_connection(target, target, "domain",
                                    em, em, "email",
                                    "whois_email")

        # Subdomains
        for sub in domain_data.get("subdomains", {}).get("subdomains", [])[:10]:
            self.add_connection(target, target, "domain",
                                sub, sub, "domain", "subdomain_of")

        # ── From username lookup ──────────────────────
        username_data = osint_data.get("username_lookup", {}).get("data", {}).get("data", {})
        for platform_hit in username_data.get("found", [])[:15]:
            plat = platform_hit.get("platform", "")
            url  = platform_hit.get("url", "")
            self.add_connection(target, target, "username",
                                url, plat, "url",
                                "found_on")

        # ── From social media ─────────────────────────
        github_data = osint_data.get("social_media", {}).get("data", {}).get("github", {})
        for repo in github_data.get("repos", [])[:5]:
            repo_url = repo.get("url", "")
            if repo_url:
                self.add_connection(target, target, "username",
                                    repo_url, repo.get("name", repo_url), "url",
                                    "owns_repo")
        if github_data.get("profile", {}).get("email"):
            em = github_data["profile"]["email"]
            self.add_connection(target, target, "username", em, em, "email",
                                "github_email")

        # ── From crypto tracer ────────────────────────
        crypto_data = osint_data.get("crypto", {}).get("data", {})
        if crypto_data.get("address"):
            self.add_connection(target, target, "person",
                                crypto_data["address"], crypto_data["address"], "crypto",
                                "owns_wallet")

        # ── From phone lookup ─────────────────────────
        phone_data = osint_data.get("phone", {}).get("data", {})
        if phone_data.get("parsed", {}).get("e164"):
            phone = phone_data["parsed"]["e164"]
            self.add_connection(target, target, "person", phone, phone, "phone",
                                "phone_number")

        # ── From email header ─────────────────────────
        header_data = osint_data.get("email_header", {}).get("data", {})
        for ip in header_data.get("ips_found", [])[:5]:
            self.add_connection(target, target, "email", ip, ip, "ip",
                                "sent_from_ip")
        for geo in header_data.get("geolocations", [])[:3]:
            if geo.get("country"):
                cid = f"country:{geo['country']}"
                self.add_connection(geo.get("ip",""), geo.get("ip",""), "ip",
                                    cid, geo["country"], "default", "located_in")

    # ──────────────────────────────────────────────────────────
    # EXPORT — INTERACTIVE HTML (pyvis)
    # ──────────────────────────────────────────────────────────
    def export_html(self, output_path: str = "output/graph.html",
                    title: str = "OSINT Entity Graph") -> str:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        try:
            from pyvis.network import Network
            net = Network(
                height="800px", width="100%",
                bgcolor="#0d1117", font_color="#c9d1d9",
                heading=title,
            )
            net.set_options(json.dumps({
                "nodes": {"borderWidth": 2, "shadow": True,
                          "font": {"size": 12, "color": "#c9d1d9"}},
                "edges": {"color": {"color": "#30363d", "highlight": "#00d4ff"},
                          "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                          "smooth": {"type": "curvedCW", "roundness": 0.2}},
                "physics": {"forceAtlas2Based": {"gravitationalConstant": -50,
                            "centralGravity": 0.01, "springLength": 120},
                            "solver": "forceAtlas2Based"},
                "interaction": {"hover": True, "navigationButtons": True, "keyboard": True},
            }))

            for nid, node in self.nodes.items():
                tooltip = f"Type: {node['type']}\nID: {nid}"
                if node.get("data"):
                    for k, v in list(node["data"].items())[:3]:
                        tooltip += f"\n{k}: {v}"
                net.add_node(nid, label=node["label"][:25],
                             color=node["color"], title=tooltip,
                             size=node.get("size", 20))

            for edge in self.edges:
                net.add_edge(edge["from"], edge["to"],
                             label=edge.get("label", ""),
                             title=edge.get("evidence", ""),
                             width=edge.get("weight", 1))

            net.write_html(output_path)
            logger.info(f"[GRAPH] Interactive HTML saved: {output_path}")
            return output_path

        except ImportError:
            logger.warning("[GRAPH] pyvis not installed — falling back to static HTML")
            return self._export_static_html(output_path, title)

    # ──────────────────────────────────────────────────────────
    # EXPORT — NETWORKX / GRAPHML
    # ──────────────────────────────────────────────────────────
    def export_graphml(self, output_path: str = "output/graph.graphml") -> str:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        try:
            import networkx as nx
            G = nx.DiGraph()
            for nid, node in self.nodes.items():
                G.add_node(nid, label=node["label"], node_type=node["type"])
            for edge in self.edges:
                G.add_edge(edge["from"], edge["to"], label=edge.get("label", ""))
            nx.write_graphml(G, output_path)
            return output_path
        except ImportError:
            return "networkx not installed"

    # ──────────────────────────────────────────────────────────
    # EXPORT — JSON
    # ──────────────────────────────────────────────────────────
    def export_json(self, output_path: str = "output/graph.json") -> str:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        graph_data = {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "stats": self.get_stats(),
            "generated": datetime.now().isoformat(),
        }
        with open(output_path, "w") as f:
            json.dump(graph_data, f, indent=2, default=str)
        return output_path

    # ──────────────────────────────────────────────────────────
    # STATS
    # ──────────────────────────────────────────────────────────
    def get_stats(self) -> Dict:
        type_counts: Dict[str, int] = {}
        for node in self.nodes.values():
            t = node["type"]
            type_counts[t] = type_counts.get(t, 0) + 1
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types":  type_counts,
        }

    def _guess_type(self, value: str) -> str:
        import re
        if re.match(r"[^@]+@[^@]+\.[^@]+", value): return "email"
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value): return "ip"
        if re.match(r"[\+]?\d{7,}", value.replace(" ", "")): return "phone"
        if "." in value: return "domain"
        return "username"

    def _export_static_html(self, output_path: str, title: str) -> str:
        """Fallback: simple static HTML graph using D3.js CDN."""
        nodes_json = json.dumps(list(self.nodes.values()), default=str)
        edges_json = json.dumps(self.edges, default=str)
        stats = self.get_stats()

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{title}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
  body{{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0}}
  svg{{width:100%;height:90vh}}
  .node circle{{stroke:#30363d;stroke-width:2px;cursor:pointer}}
  .node text{{font-size:11px;fill:#c9d1d9;pointer-events:none}}
  .link{{stroke:#30363d;stroke-opacity:0.6;fill:none}}
  .link.highlighted{{stroke:#00d4ff;stroke-width:2px}}
  #stats{{padding:10px 20px;background:#161b22;border-bottom:1px solid #30363d;font-size:12px;color:#8b949e}}
  #stats span{{margin-right:20px;color:#c9d1d9}}
</style></head><body>
<div id="stats">
  <span>Nodes: <b>{stats['total_nodes']}</b></span>
  <span>Edges: <b>{stats['total_edges']}</b></span>
  <span style="color:#8b949e">{title}</span>
</div>
<svg id="graph"></svg>
<script>
const nodes = {nodes_json};
const links = {edges_json}.map(e=>{{return{{source:e.from,target:e.to,label:e.label}}}});
const width=window.innerWidth, height=window.innerHeight*0.9;
const svg=d3.select("#graph").attr("viewBox",[0,0,width,height]);
const sim=d3.forceSimulation(nodes).force("link",d3.forceLink(links).id(d=>d.id).distance(120))
  .force("charge",d3.forceManyBody().strength(-200)).force("center",d3.forceCenter(width/2,height/2));
const link=svg.append("g").selectAll("line").data(links).join("line").attr("class","link").attr("stroke-width",1.5);
const node=svg.append("g").selectAll("g").data(nodes).join("g").attr("class","node").call(
  d3.drag().on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y}})
    .on("drag",(e,d)=>{{d.fx=e.x;d.fy=e.y}})
    .on("end",(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}}));
node.append("circle").attr("r",10).attr("fill",d=>d.color||"#666");
node.append("text").attr("dx",14).attr("dy",4).text(d=>d.label.substring(0,20));
node.append("title").text(d=>d.id+"\\nType: "+d.type);
sim.on("tick",()=>{{link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`)}});
</script></body></html>"""

        with open(output_path, "w") as f:
            f.write(html)
        return output_path
