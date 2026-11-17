
def verify_remediation(remediation_plan):

    verification_results = []

    for item in remediation_plan:

        result = item.copy()

        before_evidence = item.get("Before Evidence")
        after_evidence = item.get("After Evidence")

        # Evidence must exist on both sides
        if not before_evidence or not after_evidence:

            result["Verification Status"] = "Inconclusive"
            result["Risk Status"] = "Unknown"

        elif before_evidence == after_evidence:

            result["Verification Status"] = "Failed"
            result["Risk Status"] = "Unchanged"

        else:

            result["Verification Status"] = "Inconclusive"
            result["Risk Status"] = "Unknown"

        verification_results.append(result)

    return verification_results


def get_verification_summary(results):

    passed = sum(
        1 for item in results
        if item["Verification Status"] == "Passed"
    )

    failed = sum(
        1 for item in results
        if item["Verification Status"] == "Failed"
    )

    inconclusive = sum(
        1 for item in results
        if item["Verification Status"] == "Inconclusive"
    )

    return {
        "Total": len(results),
        "Passed": passed,
        "Failed": failed,
        "Inconclusive": inconclusive
    }
