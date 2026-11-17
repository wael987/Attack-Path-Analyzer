"""Command-line demo for the Technical Lead's attack-path deliverable."""

from src.attack_graph.graph_builder import build_attack_graph
from src.attack_graph.sample_data import CRITICAL_ASSET, ENTRY_POINT
from src.risk_scoring.risk_scorer import rank_attack_paths


def main():
    graph = build_attack_graph()
    ranked_paths = rank_attack_paths(
        graph,
        source=ENTRY_POINT,
        target=CRITICAL_ASSET,
        top_n=3,
    )

    print("ATTACK PATH ANALYSIS - SYNTHETIC FIVE-HOST DATASET")
    print("=" * 58)
    print(f"Hosts (nodes): {graph.number_of_nodes()}")
    print(f"Possible exploit transitions (edges): {graph.number_of_edges()}")
    print(f"Entry point: {ENTRY_POINT}")
    print(f"Critical asset: {CRITICAL_ASSET}")
    print("\nTop 3 ranked paths:")

    if not ranked_paths:
        print("No path was found between the selected hosts.")
        return

    for index, item in enumerate(ranked_paths, start=1):
        print(f"\n{index}. {item['path_text']}")
        print(f"   Risk score: {item['risk_score']:.2f}/100 ({item['risk_level']})")
        print(f"   Status: {item['status']}")
        print(f"   Vulnerabilities: {', '.join(item['vulnerabilities'])}")
        print(f"   Hops: {item['hops']}")

    print("\nNote: sample findings are synthetic and every sample path is hypothetical.")


if __name__ == "__main__":
    main()
