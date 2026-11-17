# Technical Lead - Attack Graph and Risk Scoring

## Scope completed

- Built a directed NetworkX attack graph using a synthetic five-host dataset.
- Added vulnerability-linked directed edges, so `A -> B` means an attacker on A may exploit a vulnerability on B.
- Used `networkx.all_simple_paths()` to find paths from the entry point to the critical database.
- Calculated edge risk, combined path risk, ranked all paths, and printed the top three.
- Kept the graph builder data-source independent so normalized records can later come from PostgreSQL.
- Added tests for the five-host dataset, ranking order, hypothetical status, unreachable-edge filtering, and score bounds.

## Graph model

- **Node:** one host/asset, identified by `host_id`; includes hostname, IP, role, and criticality.
- **Directed edge:** one possible transition from `source_host` to `target_host`, linked to a vulnerability affecting the target host.
- **Edge fields:** vulnerability ID, CVSS, exploitability factor, reachability factor, evidence confidence, validation status, and evidence note.
- Unreachable edges, rejected transitions, and explicitly not-exploitable transitions are not added. A transition with no linked vulnerability is not an attack edge.
- Version 1 expects one vulnerability record per directed host-to-host transition. If a database join returns several vulnerabilities for the same source/target pair, group those alternatives before calling this `DiGraph` builder; the current version raises an error rather than silently overwriting one of them.
- Hypothetical transitions remain available for *potential-risk ranking*, but the output labels those paths `Hypothetical`.

## Risk formula

All factors are normalized to the range 0..1 except CVSS, which uses 0..10.

`edge_risk = (CVSS / 10) * exploitability * reachability * evidence_confidence`

The edge risk is a normalized contribution, not a measured probability of compromise.

For a sequential path containing edges 1..n, every transition must succeed to reach the target:

`path_chain_strength = product(edge_risk_i)`

`path_risk_score = 100 * path_chain_strength * asset_criticality_factor`

Criticality factors:

| Criticality | Factor |
|---|---:|
| Low | 0.25 |
| Medium | 0.50 |
| High | 0.75 |
| Critical | 1.00 |

The path score is a **0..100 priority index**, not a measured real-world probability. Multiplication is used because the path is sequential: all required transitions must be feasible for the attacker to reach the target. Asset criticality increases the priority of paths that end at more important assets. Evidence confidence reduces the contribution of uncertain findings. The independence assumption is a simplification for this prototype and should be stated when presenting results.

## Why these choices

- CVSS captures vulnerability severity on a standard 0..10 scale.
- Exploitability represents how practical the transition is to exploit.
- Reachability prevents a severe weakness from contributing to an attack path when the source cannot reach the target.
- Evidence confidence accounts for whether the finding and transition are supported by reliable observations.
- Asset criticality prioritizes paths leading to high-value systems.
- Multiplying the edge factors models a sequential chain: if one required transition is weak or uncertain, the complete path becomes less feasible. It also keeps the path score bounded between 0 and 100.

## Run the demo

From the project root:

```bash
python -m pip install -r requirements.txt
python -m src.attack_graph.run_analysis
```

Run automated checks:

```bash
python -m unittest discover -s tests -v
```

Run the existing dashboard:

```bash
streamlit run main.py
```

## Synthetic sample vs. the real lab

The five-host data in `src/attack_graph/sample_data.py` is fabricated for offline development and demonstrates the complete ranking workflow. Every sample transition is marked hypothetical.

The separate `ground-truth/` files came from the team's uploaded lab notes. Those notes identify three actual lab hosts:

- H1: Kali Linux (`192.168.75.10`)
- H2: Metasploitable 2 (`192.168.75.20`)
- H3: Ubuntu database server (`192.168.75.30`)

The lab notes report network reachability, including H2-to-H3 ping success, but explicitly state that exploitability and lateral movement have not been verified. PostgreSQL is listening on localhost and port 5432 is closed from Kali. Therefore the candidate route Kali -> Metasploitable 2 -> Ubuntu DB must **not** be reported as a confirmed attack path at this stage.

## PostgreSQL integration mapping (next step)

The uploaded `schema.sql` already has the tables needed for a future adapter:

- `hosts`: node fields (`host_id`, `hostname`, `ip_address`, `role`, `criticality`).
- `network_edges`: transition endpoints and network reachability (`source_host`, `target_host`, `reachable`, `exploitable`, `evidence`).
- `vulnerabilities`: target-host finding details (`host_id`, `vulnerability_name`, `cvss_score`, `verification_status`).
- `edge_vulnerabilities`: links vulnerabilities to edges and records `hypothetical`, `validated`, or `rejected` status.

The current module deliberately does not open a database connection. To integrate it later, query those tables, normalize the rows into the same `hosts`, `vulnerabilities`, and `edges` record shapes used by `build_attack_graph()`, then pass those lists to the function. Do not translate `reachable = true` into `exploitable = true`.

The current database schema does not store a numeric exploitability factor or evidence-confidence factor. Those values must either be added as documented fields or derived through an agreed, documented mapping; do not invent them silently.
