 
#the entry point of our entire attack path analyzer
import streamlit as st
from src.discovery.asset_manager import get_assets
from src.vulnerability.vulnerability_manager import get_vulnerabilities
from src.attack_graph.graph_builder import build_attack_graph
from src.attack_graph.sample_data import CRITICAL_ASSET, ENTRY_POINT
from src.risk_scoring.risk_scorer import rank_attack_paths, score_vulnerabilities
from src.remediation.remediation_manager import (
    create_remediation_plan,
    approve_remediation,
    reject_remediation
)
from src.verification.verification_manager import (
    verify_remediation,
    get_verification_summary
)



st.set_page_config(
    page_title="Attack Path Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("Attack Path Analyzer")
st.subheader("Security Assessment and Auto-Remediation")

st.write(
    "Welcome to our Attack Path Analyzer project."
)
st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Choose a Module",
    [
        "Dashboard",
        "Asset Discovery",
        "Vulnerability Analysis",
        "Attack Graph",
        "Risk Assessment",
        "Remediation",
        "Verification"
    ]
)

if page == "Dashboard":
    st.header("Security Overview")
    st.info("Welcome to the main dashboard.")

elif page == "Asset Discovery":
    st.header("Asset Discovery")

    assets = get_assets()
    st.dataframe(assets, use_container_width=True)
    st.metric("Total Assets", len(assets))

    st.subheader("Discovered Assets")
    st.dataframe(assets, use_container_width=True)

    st.metric("Total Assets", len(assets))

elif page == "Vulnerability Analysis":
    st.header("Vulnerability Analysis")

    vulnerabilities = get_vulnerabilities()
 
    st.dataframe(vulnerabilities, use_container_width=True)

    st.metric("Total Vulnerabilities", len(vulnerabilities))
    st.write("Review detected vulnerabilities.")

elif page == "Attack Graph":
    st.header("Attack Graph")

    graph = build_attack_graph()

    st.metric("Total Nodes", graph.number_of_nodes())
    st.metric("Total Connections", graph.number_of_edges())

    st.subheader("Graph Nodes")
    st.write(list(graph.nodes()))

    st.subheader("Graph Connections")
    st.write(list(graph.edges()))

    st.subheader("Paths to Critical Asset")
    ranked_paths = rank_attack_paths(graph, ENTRY_POINT, CRITICAL_ASSET, top_n=10)
    if ranked_paths:
        st.dataframe(
            [
                {
                    "Rank": index,
                    "Path": item["path_text"],
                    "Risk Score": item["risk_score"],
                    "Risk Level": item["risk_level"],
                    "Status": item["status"],
                    "Vulnerabilities": ", ".join(item["vulnerabilities"]),
                }
                for index, item in enumerate(ranked_paths, start=1)
            ],
            use_container_width=True,
        )
    else:
        st.info("No candidate path was found for the selected entry point and asset.")
    st.caption("Synthetic demo data only. Hypothetical paths are not confirmed compromises.")

elif page == "Risk Assessment":

    st.header("Risk Assessment")

    vulnerabilities = get_vulnerabilities()

    scored_vulnerabilities = score_vulnerabilities(
        vulnerabilities
    )

    st.subheader("Risk Assessment Results")

    st.dataframe(
        scored_vulnerabilities,
        use_container_width=True
    )

    critical_count = sum(
        1 for item in scored_vulnerabilities
        if item["Risk Level"] == "Critical"
    )

    high_count = sum(
        1 for item in scored_vulnerabilities
        if item["Risk Level"] == "High"
    )

    medium_count = sum(
        1 for item in scored_vulnerabilities
        if item["Risk Level"] == "Medium"
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Critical Risks", critical_count)
    col2.metric("High Risks", high_count)
    col3.metric("Medium Risks", medium_count)

    st.subheader("Top 3 Attack Paths to the Critical Asset")
    graph = build_attack_graph()
    top_paths = rank_attack_paths(graph, ENTRY_POINT, CRITICAL_ASSET, top_n=3)
    if top_paths:
        st.dataframe(
            [
                {
                    "Rank": index,
                    "Attack Path": item["path_text"],
                    "Risk Score / 100": item["risk_score"],
                    "Risk Level": item["risk_level"],
                    "Path Status": item["status"],
                    "Vulnerabilities": ", ".join(item["vulnerabilities"]),
                }
                for index, item in enumerate(top_paths, start=1)
            ],
            use_container_width=True,
        )
    st.caption("Path risk is a prioritization score. The five-host findings are synthetic and hypothetical.")


elif page == "Remediation":

    st.header("Remediation Management")

    # Initialize the plan only once per session
    if "remediation_plan" not in st.session_state:

        vulnerabilities = get_vulnerabilities()

        st.session_state.remediation_plan = (
            create_remediation_plan(vulnerabilities)
        )

    remediation_plan = st.session_state.remediation_plan

    st.subheader("Remediation Recommendations")

    # Display each finding separately
    for item in remediation_plan:

        finding_id = item["Finding ID"]

        st.markdown(f"### {finding_id} - {item['Asset']}")

        st.write("Vulnerability:", item["Vulnerability"])
        st.write("Severity:", item["Severity"])
        st.write("Recommendation:", item["Recommendation"])

        st.write("Approval:", item["Approval Status"])
        st.write("Remediation:", item["Remediation Status"])
        st.write("Execution:", item["Execution Status"])

        col1, col2 = st.columns(2)

        with col1:

            if st.button(
                "Approve",
                key=f"approve_{finding_id}",
                disabled=item["Approval Status"] != "Pending"
            ):

                st.session_state.remediation_plan = (
                    approve_remediation(
                        st.session_state.remediation_plan,
                        finding_id
                    )
                )

                st.rerun()

        with col2:

            if st.button(
                "Reject",
                key=f"reject_{finding_id}",
                disabled=item["Approval Status"] != "Pending"
            ):

                st.session_state.remediation_plan = (
                    reject_remediation(
                        st.session_state.remediation_plan,
                        finding_id
                    )
                )

                st.rerun()

        st.divider()

    st.subheader("Remediation Plan Overview")

    st.dataframe(
        st.session_state.remediation_plan,
        use_container_width=True
    )



elif page == "Verification":

    st.header("Remediation Verification")

    vulnerabilities = get_vulnerabilities()

    remediation_plan = create_remediation_plan(
        vulnerabilities
    )

    st.info(
        "This is a demonstration using simulated remediation results."
    )

    simulated_plan = remediation_plan
    for item in remediation_plan:
        simulated_plan = approve_remediation(
            simulated_plan,
            item["Finding ID"]
        )

    results = verify_remediation(simulated_plan)

    summary = get_verification_summary(results)

    col1, col2, col3 = st.columns(3)

    col1.metric("Total", summary["Total"])
    col2.metric("Passed", summary["Passed"])
    col3.metric("Inconclusive", summary["Inconclusive"])

    st.subheader("Verification Results")

    st.dataframe(results, use_container_width=True)