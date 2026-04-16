from pathlib import Path
import pandas as pd

from agentic_patch_strategist import (
    IngestAgent,
    RiskScoringAgent,
    BusinessImpactAgent,
    DependencyAgent,
    WhatIfAgent,
    ComplianceAgent,
    SchedulerAgent,
    compute_priority_scores,
)

# =========================
# INPUT / OUTPUT SETTINGS
# =========================
INPUT_FILE = r"data\input\New_Vulnerability_Dataset.csv"
OUTPUT_EXCEL = r"data\output\ranked_patch_plan.xlsx"

RISK_APPETITE = "balanced"   # options: balanced, aggressive, conservative

# Optional what-if settings
ENABLE_EXPLOIT_SPIKE = False
WHAT_IF_CVE = "CVE-2024-24919"
WHAT_IF_EXPLOIT_PROB = 0.98

ENABLE_DELAY_SIMULATION = False
WHAT_IF_DELAY_CVE = "CVE-2024-24919"
DELAY_DAYS = 30

# Optional scheduling settings
SCHEDULE_START = None   # example: "2026-04-16"
WINDOW_DAYS = 7


def main():
    input_path = Path(INPUT_FILE)
    output_path = Path(OUTPUT_EXCEL)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Agents
    ingest_agent = IngestAgent()
    risk_agent = RiskScoringAgent()
    business_agent = BusinessImpactAgent()
    dependency_agent = DependencyAgent()
    what_if_agent = WhatIfAgent()
    compliance_agent = ComplianceAgent()
    scheduler_agent = SchedulerAgent(
        start_date=SCHEDULE_START,
        window_days=WINDOW_DAYS,
    )

    # Pipeline
    df = ingest_agent.run(str(input_path))
    df = risk_agent.run(df)

    df = what_if_agent.run(
        df,
        what_if_cve=WHAT_IF_CVE if ENABLE_EXPLOIT_SPIKE else None,
        what_if_exploit_prob=WHAT_IF_EXPLOIT_PROB,
        what_if_delay=WHAT_IF_DELAY_CVE if ENABLE_DELAY_SIMULATION else None,
        delay_days=DELAY_DAYS,
    )

    if ENABLE_EXPLOIT_SPIKE:
        df = risk_agent.run(df)

    df = business_agent.run(df)
    df = dependency_agent.run(df)
    df = compliance_agent.run(df)
    df = compute_priority_scores(df, RISK_APPETITE)
    df = scheduler_agent.run(df)

    # Make output columns cleaner for Excel
    export_df = df.copy()
    export_df["Risk Score"] = export_df["risk_score"]
    export_df["Priority Score"] = export_df["priority_score"]
    export_df["Recommended Action"] = export_df["recommended_action"]
    export_df["Recommended Patch Window"] = export_df["recommended_window"]
    export_df["Scheduled Date"] = export_df["scheduled_date"]
    export_df["Explanation"] = export_df["explanation"]
    export_df["Cascade Risk"] = export_df["cascade_risk"]
    export_df["Downstream Count"] = export_df["downstream_count"]
    export_df["Detected Compliance"] = export_df["detected_compliance"]
    export_df["Scheduling Conflict"] = export_df["scheduling_conflict"]
    export_df["What-If Note"] = export_df["what_if_note"] if "what_if_note" in export_df.columns else ""

    final_columns = [
        "CVE ID",
        "Affected System",
        "CVSS Score",
        "Severity",
        "Exploit Prob (EPSS)",
        "Criticality",
        "Tier",
        "Business Impact",
        "Dependency Score",
        "Downtime Cost",
        "Est. Effort",
        "Risk Score",
        "Priority Score",
        "Cascade Risk",
        "Downstream Count",
        "Detected Compliance",
        "Recommended Action",
        "Recommended Patch Window",
        "Scheduled Date",
        "Scheduling Conflict",
        "Vendor",
        "Patch Available",
        "SBOM Component",
        "What-If Note",
        "Explanation",
    ]

    final_columns = [col for col in final_columns if col in export_df.columns]
    export_df = export_df[final_columns]

    # Save ranked Excel
    export_df.to_excel(output_path, index=False)

    print("\nRanked Excel file created successfully.")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()