"""NetworkX graph analysis for Wi-Fi relationships.

WHY: Attack graphs make Evil Twin visible. Nodes=APs (BSSID), edges=shared SSID but different attributes.
Centrality highlights suspicious APs that mimic multiple SSIDs.
"""
from typing import List, Dict, Any
from ..scanner.models import WiFiNetwork

try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    HAS_NX = False

def build_ap_graph(networks: List[WiFiNetwork]):
    """Build graph: edge between APs sharing SSID but differing in BSSID/encryption/vendor/channel."""
    if not HAS_NX:
        return None
    G = nx.Graph()
    for n in networks:
        G.add_node(n.bssid, ssid=n.ssid, vendor=n.vendor, enc=n.short_encryption(), channel=n.channel, signal=n.signal_dbm)
    # Group by SSID
    from collections import defaultdict
    by_ssid: Dict[str, List[WiFiNetwork]] = defaultdict(list)
    for n in networks:
        by_ssid[n.ssid].append(n)
    for ssid, group in by_ssid.items():
        if len(group) < 2:
            continue
        # Connect every pair that differs in some fingerprint
        for i in range(len(group)):
            for j in range(i+1, len(group)):
                a, b = group[i], group[j]
                if a.bssid == b.bssid:
                    continue
                reasons = []
                if a.short_encryption() != b.short_encryption():
                    reasons.append("encryption_mismatch")
                if a.vendor != b.vendor:
                    reasons.append("vendor_mismatch")
                if abs(a.channel - b.channel) >= 5:
                    reasons.append("channel_far")
                # Edge weight = number of mismatches
                if reasons:
                    G.add_edge(a.bssid, b.bssid, ssid=ssid, reasons=reasons, weight=len(reasons))
    return G

def graph_insights(G) -> Dict[str, Any]:
    """Return human-readable insights from graph."""
    if G is None or G.number_of_nodes() == 0:
        return {"clusters": 0, "suspicious_pairs": 0, "most_connected": None}
    try:
        components = list(nx.connected_components(G))
        # Suspicious = connected component with >1 node sharing SSID
        suspicious_pairs = G.number_of_edges()
        # Most connected node (potential evil twin hub)
        if G.number_of_nodes() > 0:
            degrees = dict(G.degree())
            most = max(degrees, key=degrees.get) if degrees else None
            most_degree = degrees.get(most, 0) if most else 0
        else:
            most, most_degree = None, 0
        # Betweenness can reveal bridge attacker
        betweenness = nx.betweenness_centrality(G) if G.number_of_nodes() > 2 else {}
        top_bridge = max(betweenness, key=betweenness.get) if betweenness else None
        return {
            "clusters": len(components),
            "suspicious_pairs": suspicious_pairs,
            "most_connected": {"bssid": most, "degree": most_degree} if most else None,
            "top_bridge": top_bridge,
            "density": nx.density(G),
        }
    except Exception as e:
        return {"error": str(e), "clusters": 0, "suspicious_pairs": 0}
