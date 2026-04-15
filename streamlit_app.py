from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from agentic_patch_strategist import (
    apply_what_if,
    build_summary,
    load_dataset,
    prepare_dataframe,
    score_dataframe,
)

DEFAULT_DATASET_PATH = "sample_data/Agentic_AI_Dataset.csv"

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

    enable_what_if = st.checkbox("Enable what-if simulation", value=False)

    what_if_cve = ""
    what_if_exploit_prob = 0.98

    if enable_what_if:
        what_if_cve = st.text_input("CVE ID for what-if", value="")
        what_if_exploit_prob = st.slider(
            "Simulated exploit probability",
            min_value=0.0,
            max_value=1.0,
            value=0.98,
            step=0.01,
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


def run_pipeline(
    input_source: str,
    risk_appetite: str = "balanced",
    what_if_cve: str | None = None,
    what_if_exploit_prob: float = 0.98,
):
    df = load_dataset(input_source)
    df = prepare_dataframe(df)

    if what_if_cve and str(what_if_cve).strip():
        df = apply_what_if(df, str(what_if_cve).strip(), float(what_if_exploit_prob))
        df = prepare_dataframe(df)

    df = score_dataframe(df, risk_appetite)
    summary = build_summary(df, input_source, risk_appetite)
    return df, summary


try:
    if uploaded_file is not None:
        input_path = save_uploaded_file(uploaded_file)
        display_input_name = uploaded_file.name
    else:
        input_path = DEFAULT_DATASET_PATH
        display_input_name = DEFAULT_DATASET_PATH

    df, summary = run_pipeline(
        input_source=input_path,
        risk_appetite=risk_appetite,
        what_if_cve=what_if_cve if enable_what_if else None,
        what_if_exploit_prob=what_if_exploit_prob if enable_what_if else 0.98,
    )

    summary["input_file"] = display_input_name

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total vulnerabilities", summary["total_vulnerabilities"])
    c2.metric("Top priority CVE", summary["top_priority_cve"])
    c3.metric(
        "Top priority score",
        f'{summary["top_priority_score"]:.4f}' if summary["top_priority_score"] is not None else "N/A",
    )
    c4.metric("Immediate patch count", summary["immediate_patch_count"])

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
        "Business Impact",
        "Dependency Score",
        "Downtime Cost",
        "Est. Effort",
        "priority_score",
        "recommended_action",
        "recommended_window",
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

    st.subheader("Top explanations")
    for _, row in df.head(5).iterrows():
        st.markdown(
            f"**{row['CVE ID']} - {row['Affected System']}**  \n"
            f"Priority Score: `{row['priority_score']}`  \n"
            f"Action: **{row['recommended_action']}**  \n"
            f"Window: **{row['recommended_window']}**  \n"
            f"{row['explanation']}"
        )

    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download ranked patch plan (CSV)",
        data=csv_data,
        file_name="ranked_patch_plan.csv",
        mime="text/csv",
    )

except Exception as e:
    st.error(f"Error processing data: {e}")