import unittest

from src.attack_graph.graph_builder import build_attack_graph
from src.attack_graph.sample_data import CRITICAL_ASSET, ENTRY_POINT
from src.risk_scoring.risk_scorer import (
    calculate_edge_risk,
    calculate_path_risk,
    rank_attack_paths,
)


class AttackPathTests(unittest.TestCase):
    def test_sample_graph_has_five_hosts(self):
        graph = build_attack_graph()
        self.assertEqual(graph.number_of_nodes(), 5)
        self.assertGreaterEqual(graph.number_of_edges(), 5)

    def test_ranked_paths_are_descending(self):
        graph = build_attack_graph()
        paths = rank_attack_paths(graph, ENTRY_POINT, CRITICAL_ASSET, top_n=3)
        self.assertEqual(len(paths), 3)
        scores = [item["risk_score"] for item in paths]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_sample_paths_are_hypothetical(self):
        graph = build_attack_graph()
        paths = rank_attack_paths(graph, ENTRY_POINT, CRITICAL_ASSET, top_n=3)
        self.assertTrue(all(item["status"] == "Hypothetical" for item in paths))

    def test_unreachable_edge_is_not_added(self):
        hosts = [{"host_id": "A", "criticality": "low"}, {"host_id": "B", "criticality": "critical"}]
        vulnerabilities = [{
            "vulnerability_id": "V1", "host_id": "B", "cvss": 9.0,
            "exploitability": 0.9, "evidence_confidence": 1.0,
        }]
        edges = [{
            "edge_id": "E1", "source_host": "A", "target_host": "B",
            "vulnerability_id": "V1", "reachable": False,
            "reachability_factor": 1.0, "validation_status": "hypothetical",
        }]
        graph = build_attack_graph(hosts, vulnerabilities, edges)
        self.assertEqual(graph.number_of_edges(), 0)


    def test_not_exploitable_edge_is_not_added(self):
        hosts = [{"host_id": "A", "criticality": "low"}, {"host_id": "B", "criticality": "critical"}]
        vulnerabilities = [{
            "vulnerability_id": "V1", "host_id": "B", "cvss": 9.0,
            "exploitability": 0.9, "evidence_confidence": 1.0,
        }]
        edges = [{
            "edge_id": "E1", "source_host": "A", "target_host": "B",
            "vulnerability_id": "V1", "reachable": True,
            "reachability_factor": 1.0, "exploitable": "not_exploitable",
            "validation_status": "hypothetical",
        }]
        graph = build_attack_graph(hosts, vulnerabilities, edges)
        self.assertEqual(graph.number_of_edges(), 0)

    def test_edge_and_path_scores_are_bounded(self):
        edge = {
            "cvss": 10.0,
            "exploitability": 1.0,
            "reachability_factor": 1.0,
            "evidence_confidence": 1.0,
        }
        self.assertEqual(calculate_edge_risk(edge), 1.0)
        self.assertEqual(calculate_path_risk([edge], "critical"), 100.0)


if __name__ == "__main__":
    unittest.main()
