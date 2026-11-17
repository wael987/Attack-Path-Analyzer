# Attack Path Analyzer

This project contains the team's initial dashboard modules and the Technical Lead's attack-graph and path-risk implementation.

## Technical Lead demo

```bash
python -m pip install -r requirements.txt
python -m src.attack_graph.run_analysis
python -m unittest discover -s tests -v
```

## Dashboard

```bash
streamlit run main.py
```

The offline demo uses a **synthetic five-host dataset** in `src/attack_graph/sample_data.py`. It is separate from the real three-host VMware lab evidence under `ground-truth/`. See `docs/TECHNICAL_LEAD.md` for the graph model, risk formula, explanation, database mapping, and important validation notes.
