from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st

from agentic_patch_strategist import _calc_scores, _normalize, _read_input, build_summary, run_what_if

st.set_page_config(page_title="Agentic Patch Strategist", layout="wide")
st.title("Agentic Patch Strategist")
st.caption("Business-aware vulnerability prioritization demo")

sample_path = Path(__file__).parent / "sample_data" / "Agentic_AI_Dataset.csv"


def load_uploaded(file) -> pd.DataFrame:
    suffix = Path(file.name).suffix.lower()
    if suffix == ".csv":
        df = pd.read_csv(file)
    elif suffix in {".xlsx", ".xls"}:
        df = pd.read_excel(file)
    else:
        raise ValueError("Upload a CSV or Excel file.")
    return _normalize(df)


with st.sidebar:
    st.header("Controls")
    risk_appetite = st.selectbox("Risk appetite", ["conservative", "balanced", "aggressive"], index=1)
    uploaded = st.file_uploader("Upload CSV/XLSX dataset", type=["csv", "xlsx", "xls"])
    use_sample = st.checkbox("Use built-in sample data", value=uploaded is None)
    run_what_if_toggle = st.checkbox("Run what-if exploit spike")
    what_if_cve = st.text_input("CVE to spike", value="CVE-2024-3400")
    epss_increase = st.slider("EPSS increase", min_value=0.05, max_value=0.80, value=0.25, step=0.05)

try:
    if uploaded is not None:
        df = load_uploaded(uploaded)
    elif use_sample:
        df = _normalize(_read_input(sample_path))
    else:
        st.info("Upload a dataset or enable sample data.")
        st.stop()
except Exception as exc:
    st.error(f"Failed to load data: {exc}")
    st.stop()

ranked = _calc_scores(df, risk_appetite)
summary = build_summary(ranked)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Records", summary["records"])
c2.metric("Total expected loss", f"${summary['total_expected_loss']:,.0f}")
c3.metric("Systems covered", len(summary["systems_covered"]))
c4.metric("Top action", ranked.iloc[0]["recommended_action"])

st.subheader("Top recommendations")
st.dataframe(
    ranked[[
        "cve_id", "affected_system", "priority_score", "expected_loss",
        "recommended_action", "recommended_patch_window"
    ]].round({"priority_score": 3, "expected_loss": 2}),
    use_container_width=True,
)

st.subheader("Priority score by vulnerability")
chart_df = ranked[["cve_id", "priority_score"]].set_index("cve_id")
st.bar_chart(chart_df)

st.subheader("Explanations")
for _, row in ranked.head(5).iterrows():
    st.write(f"**{row['cve_id']} - {row['affected_system']}**")
    st.write(row["explanation"])

csv_bytes = ranked.to_csv(index=False).encode("utf-8")
st.download_button("Download ranked CSV", data=csv_bytes, file_name="ranked_patch_plan.csv", mime="text/csv")
st.download_button("Download summary JSON", data=json.dumps(summary, indent=2), file_name="summary.json", mime="application/json")

if run_what_if_toggle:
    st.subheader("What-if simulation")
    try:
        baseline, scenario = run_what_if(df, what_if_cve, epss_increase, risk_appetite)
        compare = baseline[["cve_id", "priority_score"]].merge(
            scenario[["cve_id", "priority_score", "score_delta"]],
            on="cve_id",
            suffixes=("_baseline", "_scenario"),
        ).sort_values("score_delta", ascending=False)
        st.dataframe(compare.round(3), use_container_width=True)

        out = BytesIO()
        compare.to_csv(out, index=False)
        st.download_button(
            "Download what-if comparison CSV",
            data=out.getvalue(),
            file_name="what_if_comparison.csv",
            mime="text/csv",
        )
    except Exception as exc:
        st.error(f"What-if simulation failed: {exc}")
