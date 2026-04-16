from __future__ import annotations

import sys
import tempfile
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.append(str(CURRENT_DIR))

import streamlit as st

from agentic_patch_strategist import (
    IngestAgent,
    RiskScoringAgent,
    BusinessImpactAgent,
    DependencyAgent,
    CustomerImpactAgent,
    WhatIfAgent,
    ComplianceAgent,
    SchedulerAgent,
    compute_priority_scores,
)

DEFAULT_DATASET_PATH = CURRENT_DIR / "sample_data" / "Agentic_AI_Dataset.csv"

st.set_page_config(page_title="Agentic Patch Strategist", layout="wide")

st.title("Agentic Patch Strategist")
st.caption("Business-aware, dependency-aware vulnerability prioritization")


with st.sidebar:
    st.header("Controls")

    risk_appetite = st.selectbox(
        "Risk appetite",
        ["balanced", "aggressive", "conservative"],
        index=0,
    )

    enable_what_if_spike = st.checkbox("Enable exploit spike simulation", value=False)
    what_if_cve = ""
    what_if_exploit_prob = 0.98

    if enable_what_if_spike:
        what_if_cve = st.text_input("CVE ID for exploit spike", value="")
        what_if_exploit_prob = st.slider(
            "Simulated exploit probability",
            min_value=0.0,
            max_value=1.0,
            value=0.98,
            step=0.01,
        )

    enable_delay = st.checkbox("Enable patch delay simulation", value=False)
    what_if_delay = ""
    delay_days = 30

    if enable_delay:
        what_if_delay = st.text_input("CVE ID for patch delay", value="")
        delay_days = st.number_input(
            "Delay days",
            min_value=1,
            max_value=365,
            value=30,
            step=1,
        )

    schedule_start = st.text_input("Schedule start date (YYYY-MM-DD)", value="")
    window_days = st.number_input(
        "Days between maintenance windows",
        min_value=1,
        max_value=30,
        value=7,
        step=1,
    )


uploaded_file = st.file_uploader(
    "Upload CSV/XLSX dataset",
    type=["csv", "xlsx", "xls"],
)

st.info(
    "Expected columns: CVE ID, CVSS Score, Severity, Exploit Prob (EPSS), "
    "Affected System, Criticality, Business Impact, Dependency Score, "
    "Downtime Cost, Est. Effort, Tier, Compliance Tags, Rollback Risk, "
    "Vendor, Patch Available, SBOM Component, Maintenance Window, "
    "Customer Impact, Description, Expected Loss, Downtime Sensitivity, Cascade Risk"
)


def save_uploaded_file(uploaded_file) -> str:
    suffix = Path(uploaded_file.name).suffix.lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getbuffer())
        return tmp.name


def run_pipeline(
    input_source,
    risk_appetite: str = "balanced",
    what_if_cve: str | None = None,
    what_if_exploit_prob: float = 0.98,
    what_if_delay: str | None = None,
    delay_days: int = 30,
    schedule_start: str | None = None,
    window_days: int = 7,
):
    ingest_agent = IngestAgent()
    risk_agent = RiskScoringAgent()
    business_agent = BusinessImpactAgent()
    dependency_agent = DependencyAgent()
    customer_agent = CustomerImpactAgent()
    what_if_agent = WhatIfAgent()
    compliance_agent = ComplianceAgent()
    scheduler_agent = SchedulerAgent(
        start_date=schedule_start if schedule_start else None,
        window_days=window_days,
    )

    df = ingest_agent.run(str(input_source))
    df = risk_agent.run(df)

    df = what_if_agent.run(
        df,
        what_if_cve=what_if_cve if what_if_cve and str(what_if_cve).strip() else None,
        what_if_exploit_prob=float(what_if_exploit_prob),
        what_if_delay=what_if_delay if what_if_delay and str(what_if_delay).strip() else None,
        delay_days=int(delay_days),
    )

    if what_if_cve and str(what_if_cve).strip():
        df = risk_agent.run(df)

    df = business_agent.run(df)
    df = dependency_agent.run(df)
    df = customer_agent.run(df)
    df = compliance_agent.run(df)
    df = compute_priority_scores(df, risk_appetite, aggressive_escalation=True)
    df = scheduler_agent.run(df)

    return df


def build_summary(df, input_name: str, risk_appetite: str):
    return {
        "input_file": input_name,
        "risk_appetite": risk_appetite,
        "total_vulnerabilities": int(len(df)),
        "top_priority_cve": str(df.iloc[0]["CVE ID"]) if len(df) else "N/A",
        "top_priority_score": float(df.iloc[0]["priority_score"]) if len(df) else None,
        "p1_critical_count": int((df["risk_tier"] == "P1 – Critical").sum()) if "risk_tier" in df.columns else 0,
        "immediate_patch_count": int((df["recommended_action"] == "Patch immediately").sum()) if "recommended_action" in df.columns else 0,
        "next_window_count": int((df["recommended_action"] == "Patch in next maintenance window").sum()) if "recommended_action" in df.columns else 0,
        "schedule_monitor_count": int((df["recommended_action"] == "Schedule and monitor").sum()) if "recommended_action" in df.columns else 0,
        "monitor_count": int((df["recommended_action"] == "Monitor for now").sum()) if "recommended_action" in df.columns else 0,
        "compliance_exposed_count": int((df["detected_compliance"].fillna("") != "").sum()) if "detected_compliance" in df.columns else 0,
        "conflict_count": int(df["scheduling_conflict"].sum()) if "scheduling_conflict" in df.columns else 0,
    }


try:
    if uploaded_file is not None:
        input_path = save_uploaded_file(uploaded_file)
        display_input_name = uploaded_file.name
    else:
        input_path = DEFAULT_DATASET_PATH
        display_input_name = DEFAULT_DATASET_PATH.name

    df = run_pipeline(
        input_source=input_path,
        risk_appetite=risk_appetite,
        what_if_cve=what_if_cve if enable_what_if_spike else None,
        what_if_exploit_prob=what_if_exploit_prob if enable_what_if_spike else 0.98,
        what_if_delay=what_if_delay if enable_delay else None,
        delay_days=delay_days if enable_delay else 30,
        schedule_start=schedule_start if schedule_start.strip() else None,
        window_days=int(window_days),
    )

    summary = build_summary(df, display_input_name, risk_appetite)

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total vulnerabilities", summary["total_vulnerabilities"])
    c2.metric("Top priority CVE", summary["top_priority_cve"])
    c3.metric(
        "Top priority score",
        f'{summary["top_priority_score"]:.2f}/10' if summary["top_priority_score"] is not None else "N/A",
    )
    c4.metric("P1 Critical", summary["p1_critical_count"])
    c5.metric("Immediate patch count", summary["immediate_patch_count"])
    c6.metric("Conflicts", summary["conflict_count"])

    st.subheader("Dataset in use")
    st.write(summary["input_file"])

    st.subheader("Top recommendations")
    display_cols = [
        "CVE ID",
        "Affected System",
        "CVSS Score",
        "Severity",
        "Exploit Prob (EPSS)",
        "Criticality",
        "Tier",
        "Business Impact",
        "Dependency Score",
        "Expected Loss",
        "cascade_risk",
        "downstream_count",
        "detected_compliance",
        "customer_impact_norm",
        "priority_score",
        "risk_tier",
        "recommended_action",
        "recommended_window",
        "scheduled_date",
        "schedule_slot",
        "scheduling_conflict",
        "what_if_note",
        "Vendor",
        "Patch Available",
        "SBOM Component",
        "Description",
        "explanation",
    ]
    display_cols = [col for col in display_cols if col in df.columns]
    st.dataframe(df[display_cols])

    st.subheader("Priority score by vulnerability")
    chart_df = df[["CVE ID", "priority_score"]].set_index("CVE ID")
    st.bar_chart(chart_df)

    st.subheader("Recommended action breakdown")
    action_counts = (
        df["recommended_action"]
        .value_counts()
        .rename_axis("Action")
        .reset_index(name="Count")
    )
    st.dataframe(action_counts)

    if "risk_tier" in df.columns:
        st.subheader("Risk tier breakdown")
        tier_counts = (
            df["risk_tier"]
            .value_counts()
            .rename_axis("Risk Tier")
            .reset_index(name="Count")
        )
        st.dataframe(tier_counts)

    if "detected_compliance" in df.columns:
        st.subheader("Compliance exposure preview")
        compliance_view = df[
            ["CVE ID", "Affected System", "detected_compliance", "recommended_action", "scheduled_date"]
        ].copy()
        compliance_view = compliance_view[compliance_view["detected_compliance"].fillna("") != ""]
        if len(compliance_view) > 0:
            st.dataframe(compliance_view)
        else:
            st.write("No compliance exposure detected in the current dataset.")

    st.subheader("Top explanations")
    for _, row in df.head(5).iterrows():
        st.markdown(
            f"**{row['CVE ID']} - {row['Affected System']}**  \n"
            f"Priority Score: `{row['priority_score']:.2f}/10`  \n"
            f"Risk Tier: **{row.get('risk_tier', 'N/A')}**  \n"
            f"Action: **{row['recommended_action']}**  \n"
            f"Window: **{row['recommended_window']}**  \n"
            f"Scheduled Date: **{row['scheduled_date']}**  \n"
            f"Slot: **{row.get('schedule_slot', 'N/A')}**  \n"
            f"{row['explanation']}"
        )
        if "what_if_note" in row and str(row["what_if_note"]).strip():
            st.markdown(f"**What-If Note:** {row['what_if_note']}")

    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download ranked patch plan (CSV)",
        data=csv_data,
        file_name="ranked_patch_plan.csv",
        mime="text/csv",
    )

except Exception as e:
    st.error(f"Error processing data: {e}")