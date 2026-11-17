"""Build a directed attack graph from host, vulnerability, and edge records."""

import networkx as nx

from src.attack_graph.sample_data import EDGES, HOSTS, VULNERABILITIES


def build_attack_graph(hosts=None, vulnerabilities=None, edges=None):
    """Return a directed graph whose edges are possible exploit transitions.

    The function accepts normalized records, so the same builder can later be
    fed by PostgreSQL queries instead of the bundled synthetic sample.

    A transition is included only when it is reachable, has a vulnerability,
    and has a non-zero exploitability factor. Hypothetical transitions are kept
    for risk analysis, but their validation status remains attached to the edge.
    """
    hosts = HOSTS if hosts is None else hosts
    vulnerabilities = VULNERABILITIES if vulnerabilities is None else vulnerabilities
    edges = EDGES if edges is None else edges

    graph = nx.DiGraph()

    host_ids = set()
    for host in hosts:
        host_id = host["host_id"]
        host_ids.add(host_id)
        graph.add_node(host_id, **host)

    vulnerability_by_id = {
        vulnerability["vulnerability_id"]: vulnerability
        for vulnerability in vulnerabilities
    }

    for edge in edges:
        source = edge["source_host"]
        target = edge["target_host"]

        if source not in host_ids or target not in host_ids:
            raise ValueError(
                f"Edge {edge.get('edge_id', '?')} references an unknown host: "
                f"{source} -> {target}"
            )

        if not edge.get("reachable", False):
            continue

        if edge.get("validation_status", "hypothetical") == "rejected":
            continue
        if edge.get("exploitable") == "not_exploitable":
            continue

        vulnerability_id = edge.get("vulnerability_id")
        vulnerability = vulnerability_by_id.get(vulnerability_id)
        if vulnerability is None:
            # A transition without a linked vulnerability is not an attack edge.
            continue

        vulnerability_status = vulnerability.get("verification_status", "unknown")
        if vulnerability_status in {"not_confirmed", "rejected", "not_exploitable"}:
            continue

        exploitability = float(vulnerability.get("exploitability", 0.0))
        reachability = float(edge.get("reachability_factor", 1.0))

        if not 0.0 <= exploitability <= 1.0:
            raise ValueError(f"Exploitability for {vulnerability_id} must be 0..1")
        if not 0.0 <= reachability <= 1.0:
            raise ValueError(f"Reachability factor for {edge.get('edge_id')} must be 0..1")
        if exploitability == 0.0 or reachability == 0.0:
            continue

        # The vulnerability must affect the host being entered by this edge.
        if vulnerability.get("host_id") != target:
            raise ValueError(
                f"{vulnerability_id} belongs to {vulnerability.get('host_id')}, "
                f"but edge {source}->{target} targets {target}"
            )

        cvss = float(vulnerability.get("cvss", 0.0))
        evidence_confidence = float(vulnerability.get("evidence_confidence", 1.0))
        if not 0.0 <= cvss <= 10.0:
            raise ValueError(f"CVSS for {vulnerability_id} must be 0..10")
        if not 0.0 <= evidence_confidence <= 1.0:
            raise ValueError(f"Evidence confidence for {vulnerability_id} must be 0..1")

        if graph.has_edge(source, target):
            raise ValueError(
                f"More than one vulnerability record maps to {source}->{target}. "
                "Group vulnerability alternatives before building this DiGraph."
            )

        graph.add_edge(
            source,
            target,
            **edge,
            vulnerability_name=vulnerability.get("name", "Unknown vulnerability"),
            cvss=cvss,
            exploitability=exploitability,
            evidence_confidence=evidence_confidence,
            vulnerability_status=vulnerability.get("verification_status", "unknown"),
        )

    return graph
