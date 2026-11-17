def get_remediation_recommendation(vulnerability):

    recommendations = {
        "Outdated Software":
            "Plan and apply an approved software update.",

        "Weak Configuration":
            "Review and strengthen the security configuration.",

        "Missing Security Update":
            "Install the appropriate security update after testing."
    }

    return recommendations.get(
        vulnerability,
        "Manual security review required."
    )


def create_remediation_plan(vulnerabilities):

    remediation_plan = []

    for index, item in enumerate(vulnerabilities, start=1):

        plan = {
            "Finding ID": f"F-{index:03}",
            "Asset": item["Asset"],
            "Vulnerability": item["Vulnerability"],
            "Severity": item["Severity"],
            "Recommendation": get_remediation_recommendation(
                item["Vulnerability"]
            ),
            "Approval Status": "Pending",
            "Remediation Status": "Not Started",
            "Execution Status": "Not Executed"
        }

        remediation_plan.append(plan)

    return remediation_plan


def set_remediation_approval(plan, finding_id, decision):

    if decision not in ["Approved", "Rejected"]:
        raise ValueError("Decision must be Approved or Rejected.")

    updated_plan = []

    for item in plan:

        updated_item = item.copy()

        if updated_item["Finding ID"] == finding_id:

            updated_item["Approval Status"] = decision

            if decision == "Approved":
                updated_item["Remediation Status"] = "Awaiting Execution"

            else:
                updated_item["Remediation Status"] = "Not Started"

            # Approval does not execute the remediation.
            updated_item["Execution Status"] = "Not Executed"

        updated_plan.append(updated_item)

    return updated_plan


def approve_remediation(plan, finding_id):

    return set_remediation_approval(
        plan,
        finding_id,
        "Approved"
    )


def reject_remediation(plan, finding_id):

    return set_remediation_approval(
        plan,
        finding_id,
        "Rejected"
    )