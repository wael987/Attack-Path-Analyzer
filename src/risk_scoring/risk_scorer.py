"""Vulnerability and attack-path risk scoring."""

import math

import networkx as nx


CRITICALITY_FACTORS = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}


def calculate_risk(severity):
    """Legacy severity score used by the existing vulnerability page."""
    risk_scores = {
        "Critical": 10,
        "High": 8,
        "Medium": 5,
        "Low": 2,
    }
    return risk_scores.get(severity, 0)


def get_risk_level(score):
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def score_vulnerabilities(vulnerabilities):
    """Keep compatibility with the original vulnerability-risk screen."""
    scored_vulnerabilities = []
    for vulnerability in vulnerabilities:
        score = calculate_risk(vulnerability["Severity"])
        result = vulnerability.copy()
        result["Risk Score"] = score
        result["Risk Level"] = get_risk_level(score)
        scored_vulnerabilities.append(result)
    return scored_vulnerabilities


def calculate_edge_risk(edge):
    """Calculate one edge's normalized risk contribution (0.0 to 1.0).

    Formula:
        (CVSS / 10) * exploitability * reachability * evidence_confidence

    All factors except CVSS are normalized to 0..1.
    """
    cvss = float(edge["cvss"])
    exploitability = float(edge["exploitability"])
    reachability = float(edge.get("reachability_factor", 1.0))
    evidence_confidence = float(edge.get("evidence_confidence", 1.0))

    if not 0.0 <= cvss <= 10.0:
        raise ValueError("CVSS must be between 0 and 10")
    for label, factor in (
        ("exploitability", exploitability),
        ("reachability", reachability),
        ("evidence_confidence", evidence_confidence),
    ):
        if not 0.0 <= factor <= 1.0:
            raise ValueError(f"{label} must be between 0 and 1")

    return (cvss / 10.0) * exploitability * reachability * evidence_confidence


def calculate_path_risk(edge_data_list, asset_criticality):
    """Return a 0..100 path-priority score, not a real-world probability.

    A path is a sequence: every transition must work to reach the target.
    Therefore its chain strength is the product of its edge-risk factors.
    The chain strength is then weighted by destination asset criticality.
    """
    if not edge_data_list:
        return 0.0

    criticality = CRITICALITY_FACTORS.get(str(asset_criticality).lower())
    if criticality is None:
        raise ValueError(
            "Asset criticality must be low, medium, high, or critical"
        )

    edge_risks = [calculate_edge_risk(edge) for edge in edge_data_list]
    chain_strength = math.prod(edge_risks)
    return round(100.0 * chain_strength * criticality, 2)


def rank_attack_paths(graph, source, target, top_n=3):
    """Find simple paths with NetworkX and return them from highest to lowest risk."""
    if source not in graph:
        raise ValueError(f"Entry point '{source}' is not present in the graph")
    if target not in graph:
        raise ValueError(f"Target asset '{target}' is not present in the graph")
    if top_n < 1:
        raise ValueError("top_n must be at least 1")

    ranked_paths = []
    target_criticality = graph.nodes[target].get("criticality", "medium")

    for node_path in nx.all_simple_paths(graph, source=source, target=target):
        edge_data_list = [
            graph.get_edge_data(node_path[index], node_path[index + 1])
            for index in range(len(node_path) - 1)
        ]
        score = calculate_path_risk(edge_data_list, target_criticality)
        validation_statuses = {
            edge.get("validation_status", "hypothetical")
            for edge in edge_data_list
        }
        path_status = (
            "Validated"
            if validation_statuses == {"validated"}
            and all(edge.get("vulnerability_status") == "confirmed" for edge in edge_data_list)
            else "Hypothetical"
        )

        ranked_paths.append(
            {
                "path": node_path,
                "path_text": " -> ".join(node_path),
                "risk_score": score,
                "risk_level": get_path_risk_level(score),
                "status": path_status,
                "vulnerabilities": [edge.get("vulnerability_id") for edge in edge_data_list],
                "vulnerability_names": [edge.get("vulnerability_name") for edge in edge_data_list],
                "edge_risks": [round(calculate_edge_risk(edge), 4) for edge in edge_data_list],
                "asset_criticality": target_criticality,
                "hops": len(node_path) - 1,
            }
        )

    ranked_paths.sort(key=lambda item: (-item["risk_score"], item["path_text"]))
    return ranked_paths[:top_n]


def get_path_risk_level(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"
