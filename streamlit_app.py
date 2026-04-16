from __future__ import annotations

import sys
import tempfile
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.append(str(CURRENT_DIR))

import streamlit as st

from agentic_patch_strategist import (
    load_dataset,
    prepare_dataframe,
    apply_what_if,
    score_dataframe,
    build_summary,
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
    "Downtime Cost, Est. Effort"
)


def save_uploaded_file(uploaded_file) -> str:
    suffix = Path(uploaded_file.name).suffix.lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getbuffer())
        return tmp.name


def derive_tier_from_criticality(criticality: str) -> str:
    mapping = {
        "critical": "Tier 1",
        "high": "Tier 1",
        "medium": "Tier 2",
        "moderate": "Tier 2",
        "low": "Tier 3",
    }
    return mapping.get(str(criticality).strip().lower(), "Tier 2")


def derive_risk_tier(priority_score: float) -> str:
    if priority_score >= 0.75:
        return "P1 - Critical"
    if priority_score >= 0.55:
        return "P2 - High"
    if priority_score >= 0.35:
        return "P3 - Medium"
    return "P4 - Low"


def detect_compliance(system_name: str) -> str:
    s = str(system_name).lower()
    tags = []

    if any(x in s for x in ["payment", "billing", "checkout", "card"]):
        tags.append("PCI-DSS")
    if any(x in s for x in ["login", "auth", "identity", "user"]):
        tags.append("GDPR")
    if any(x in s for x in ["health", "patient", "medical"]):
        tags.append("HIPAA")
    if any(x in s for x in ["finance", "ledger", "accounting", "report"]):
        tags.append("SOX")

    return ", ".join(tags)


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
    df = load_dataset(str(input_source))
    df = prepare_dataframe(df)

    if what_if_cve and str(what_if_cve).strip():
        df = apply_what_if(df, str(what_if_cve).strip(), float(what_if_exploit_prob))
        df = prepare_dataframe(df)

    df = score_dataframe(df, risk_appetite)

    # Clean derived fields for display
    if "Tier" not in df.columns:
        df["Tier"] = df["Criticality"].apply(derive_tier_from_criticality)
    else:
        df["Tier"] = df["Tier"].fillna("").astype(str)
        blank_tier_mask = df["Tier"].str.strip() == ""
        df.loc[blank_tier_mask, "Tier"] = df.loc[blank_tier_mask, "Criticality"].apply(
            derive_tier_from_criticality
        )

    df["Expected Loss"] = (
        df["CVSS Score"].fillna(5.0).astype(float)
        * df["Exploit Prob (EPSS)"].fillna(0.5).astype(float)
        * df["Business Impact"].fillna(50.0).astype(float)
    ).round(2)

    df["cascade_risk"] = df["dependency_score_norm"].fillna(0.0).round(4)
    df["downstream_count"] = (
        (df["Dependency Score"].fillna(0).astype(float) - 1).clip(lower=0).astype(int)
    )

    df["detected_compliance"] = df["Affected System"].apply(detect_compliance)

    if "customer_impact_norm" not in df.columns:
        df["customer_impact_norm"] = df["Affected System"].astype(str).str.lower().apply(
            lambda s: 0.9 if any(x in s for x in ["payment", "login", "auth", "frontend", "api"])
            else 0.5
        )

    if "risk_tier" not in df.columns:
        df["risk_tier"] = df["priority_score"].apply(derive_risk_tier)

    if schedule_start and str(schedule_start).strip():
        immediate_date = str(schedule_start).strip()
    else:
        immediate_date = "Next available window"

    df["scheduled_date"] = df["recommended_action"].map({
        "Patch immediately": immediate_date,
        "Patch in next maintenance window": "Next maintenance window",
        "Schedule and monitor": "Planned low-traffic window",
        "Monitor for now": "Deferred",
    }).fillna("Deferred")

    df["schedule_slot"] = df["recommended_action"].map({
        "Patch immediately": "Emergency Slot 1",
        "Patch in next maintenance window": "Standard Slot 1",
        "Schedule and monitor": "Planned Slot 1",
        "Monitor for now": "N/A",
    }).fillna("N/A")

    df["scheduling_conflict"] = False

    if "what_if_note" not in df.columns:
        df["what_if_note"] = ""

    if what_if_delay and str(what_if_delay).strip():
        mask = df["CVE ID"].astype(str).str.strip().str.lower() == str(what_if_delay).strip().lower()
        if mask.any():
            df.loc[mask, "what_if_note"] = f"Delay simulation: patch delayed by {int(delay_days)} days."

    return df


def build_app_summary(df, input_name: str, risk_appetite: str):
    base_summary = build_summary(df, input_name, risk_appetite)
    base_summary["p1_critical_count"] = int((df["risk_tier"] == "P1 - Critical").sum()) if "risk_tier" in df.columns else 0
    base_summary["schedule_monitor_count"] = int((df["recommended_action"] == "Schedule and monitor").sum()) if "recommended_action" in df.columns else 0
    base_summary["compliance_exposed_count"] = int((df["detected_compliance"].fillna("") != "").sum()) if "detected_compliance" in df.columns else 0
    base_summary["conflict_count"] = int(df["scheduling_conflict"].sum()) if "scheduling_conflict" in df.columns else 0
    return base_summary


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

    summary = build_app_summary(df, display_input_name, risk_appetite)

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total vulnerabilities", summary["total_vulnerabilities"])
    c2.metric("Top priority CVE", summary["top_priority_cve"])
    c3.metric(
        "Top priority score",
        f'{summary["top_priority_score"]:.4f}' if summary["top_priority_score"] is not None else "N/A",
    )
    c4.metric("P1 Critical", summary["p1_critical_count"])
    c5.metric("Immediate patch count", summary["immediate_patch_count"])
    c6.metric("Compliance Exposed", summary["compliance_exposed_count"])

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
        "priority_score",
        "risk_tier",
        "recommended_action",
        "recommended_window",
        "scheduled_date",
        "what_if_note",
        "explanation",
    ]
    display_cols = [col for col in display_cols if col in df.columns]
    st.dataframe(df[display_cols], use_container_width=True)

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
    st.dataframe(action_counts, use_container_width=True)

    st.subheader("Risk tier breakdown")
    tier_counts = (
        df["risk_tier"]
        .value_counts()
        .rename_axis("Risk Tier")
        .reset_index(name="Count")
    )
    st.dataframe(tier_counts, use_container_width=True)

    st.subheader("Compliance exposure preview")
    compliance_view = df[
        ["CVE ID", "Affected System", "detected_compliance", "recommended_action", "scheduled_date"]
    ].copy()
    compliance_view = compliance_view[compliance_view["detected_compliance"].fillna("") != ""]
    if len(compliance_view) > 0:
        st.dataframe(compliance_view, use_container_width=True)
    else:
        st.write("No compliance exposure detected in the current dataset.")

    st.subheader("Top explanations")
    for _, row in df.head(5).iterrows():
        st.markdown(
            f"**{row['CVE ID']} - {row['Affected System']}**  \n"
            f"Priority Score: `{row['priority_score']:.4f}`  \n"
            f"Risk Tier: **{row.get('risk_tier', 'N/A')}**  \n"
            f"Action: **{row['recommended_action']}**  \n"
            f"Window: **{row['recommended_window']}**  \n"
            f"Scheduled Date: **{row['scheduled_date']}**  \n"
            f"{row['explanation']}"
        )
        if str(row.get("what_if_note", "")).strip():
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