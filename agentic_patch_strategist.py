from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd


SEVERITY_MAP = {
    "low": 0.25,
    "medium": 0.50,
    "moderate": 0.50,
    "high": 0.75,
    "critical": 1.00,
}


COLUMN_ALIASES = {
    "cve id": "CVE ID",
    "cve": "CVE ID",
    "cve_id": "CVE ID",

    "cvss score": "CVSS Score",
    "cvss": "CVSS Score",
    "cvss_score": "CVSS Score",

    "severity": "Severity",

    "exploit prob (epss)": "Exploit Prob (EPSS)",
    "exploit probability": "Exploit Prob (EPSS)",
    "exploit_prob": "Exploit Prob (EPSS)",
    "exploit_prob_epss": "Exploit Prob (EPSS)",
    "epss": "Exploit Prob (EPSS)",

    "affected system": "Affected System",
    "system": "Affected System",
    "affected_system": "Affected System",

    "criticality": "Criticality",
    "system criticality": "Criticality",

    "business impact": "Business Impact",
    "business_impact": "Business Impact",

    "dependency score": "Dependency Score",
    "dependency_score": "Dependency Score",

    "downtime cost": "Downtime Cost",
    "downtime_cost": "Downtime Cost",

    "est. effort": "Est. Effort",
    "estimated effort": "Est. Effort",
    "effort": "Est. Effort",
    "est_effort": "Est. Effort",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Agentic Patch Strategist - vulnerability prioritization engine"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input CSV or XLSX dataset",
    )
    parser.add_argument(
        "--output",
        default="ranked_patch_plan.csv",
        help="Path to ranked output CSV",
    )
    parser.add_argument(
        "--summary-json",
        default=None,
        help="Optional path to summary JSON output",
    )
    parser.add_argument(
        "--risk-appetite",
        choices=["conservative", "balanced", "aggressive"],
        default="balanced",
        help="Risk posture used to adjust scoring weights",
    )
    parser.add_argument(
        "--what-if-cve",
        default=None,
        help="Optional CVE ID to simulate an exploit spike",
    )
    parser.add_argument(
        "--what-if-exploit-prob",
        type=float,
        default=0.98,
        help="Exploit probability to assign during what-if simulation",
    )
    return parser.parse_args()


def load_dataset(path: str) -> pd.DataFrame:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(file_path)
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(file_path)

    raise ValueError("Unsupported file type. Use CSV or XLSX.")


def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename_map: Dict[str, str] = {}

    for col in df.columns:
        normalized = str(col).strip().lower()
        if normalized in COLUMN_ALIASES:
            rename_map[col] = COLUMN_ALIASES[normalized]

    return df.rename(columns=rename_map)


def add_missing_columns(df: pd.DataFrame) -> pd.DataFrame:
    defaults = {
        "CVE ID": [f"CVE-AUTO-{i+1:04d}" for i in range(len(df))],
        "CVSS Score": 5.0,
        "Severity": "Medium",
        "Exploit Prob (EPSS)": 0.50,
        "Affected System": "Unknown System",
        "Criticality": "Medium",
        "Business Impact": 0.50,
        "Dependency Score": 0.50,
        "Downtime Cost": 1000.0,
        "Est. Effort": 1.0,
    }

    for col, default_value in defaults.items():
        if col not in df.columns:
            df[col] = default_value

    return df


def clean_numeric(series: pd.Series, default: float) -> pd.Series:
    cleaned = pd.to_numeric(series, errors="coerce")
    return cleaned.fillna(default).astype(float)


def map_severity_to_numeric(severity: pd.Series) -> pd.Series:
    return (
        severity.astype(str)
        .str.strip()
        .str.lower()
        .map(SEVERITY_MAP)
        .fillna(0.50)
        .astype(float)
    )


def map_criticality_to_numeric(criticality: pd.Series) -> pd.Series:
    return (
        criticality.astype(str)
        .str.strip()
        .str.lower()
        .map(SEVERITY_MAP)
        .fillna(0.50)
        .astype(float)
    )


def min_max_normalize(series: pd.Series) -> pd.Series:
    series = series.astype(float)
    min_val = series.min()
    max_val = series.max()

    if pd.isna(min_val) or pd.isna(max_val):
        return pd.Series([0.5] * len(series), index=series.index, dtype=float)

    if max_val == min_val:
        return pd.Series([0.5] * len(series), index=series.index, dtype=float)

    return (series - min_val) / (max_val - min_val)


def apply_what_if(
    df: pd.DataFrame,
    what_if_cve: Optional[str],
    what_if_exploit_prob: float,
) -> pd.DataFrame:
    if not what_if_cve:
        return df

    df = df.copy()
    mask = df["CVE ID"].astype(str).str.strip().str.lower() == what_if_cve.strip().lower()
    if mask.any():
        df.loc[mask, "Exploit Prob (EPSS)"] = float(what_if_exploit_prob)
    return df


def get_weight_profile(risk_appetite: str) -> Dict[str, float]:
    if risk_appetite == "aggressive":
        return {
            "risk": 0.45,
            "business": 0.22,
            "dependency": 0.18,
            "exploit_bonus": 0.18,
            "downtime_penalty": 0.07,
            "effort_penalty": 0.03,
        }

    if risk_appetite == "conservative":
        return {
            "risk": 0.34,
            "business": 0.27,
            "dependency": 0.22,
            "exploit_bonus": 0.12,
            "downtime_penalty": 0.13,
            "effort_penalty": 0.08,
        }

    return {
        "risk": 0.40,
        "business": 0.25,
        "dependency": 0.20,
        "exploit_bonus": 0.15,
        "downtime_penalty": 0.10,
        "effort_penalty": 0.05,
    }


def build_explanation(row: pd.Series) -> str:
    reasons: List[str] = []

    if row["risk_score"] >= 0.75:
        reasons.append("high technical risk")
    elif row["risk_score"] >= 0.55:
        reasons.append("moderate-to-high technical risk")

    if row["business_impact_norm"] >= 0.75:
        reasons.append("high business impact")
    elif row["business_impact_norm"] >= 0.55:
        reasons.append("meaningful business impact")

    if row["dependency_score_norm"] >= 0.75:
        reasons.append("strong dependency risk")
    elif row["dependency_score_norm"] >= 0.55:
        reasons.append("notable downstream dependency exposure")

    if row["exploit_prob_norm"] >= 0.75:
        reasons.append("high exploit likelihood")

    if row["downtime_cost_norm"] <= 0.35:
        reasons.append("relatively low downtime cost")

    if row["effort_norm"] <= 0.35:
        reasons.append("low implementation effort")

    if not reasons:
        reasons.append("balanced overall trade-off across risk, impact, and cost")

    return "Prioritized due to " + ", ".join(reasons) + "."


def recommend_action(priority_score: float) -> str:
    if priority_score >= 0.75:
        return "Patch immediately"
    if priority_score >= 0.55:
        return "Patch in next maintenance window"
    if priority_score >= 0.35:
        return "Schedule and monitor"
    return "Monitor for now"


def recommend_window(priority_score: float, downtime_norm: float) -> str:
    if priority_score >= 0.75 and downtime_norm <= 0.40:
        return "Immediate low-risk window"
    if priority_score >= 0.75:
        return "Urgent controlled window"
    if priority_score >= 0.55:
        return "Next scheduled maintenance window"
    if priority_score >= 0.35:
        return "Planned low-traffic window"
    return "Defer until conditions change"


def prepare_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = standardize_columns(df)
    df = add_missing_columns(df)

    df = df.copy()

    df["CVSS Score"] = clean_numeric(df["CVSS Score"], 5.0).clip(0, 10)
    df["Exploit Prob (EPSS)"] = clean_numeric(df["Exploit Prob (EPSS)"], 0.50).clip(0, 1)
    df["Business Impact"] = clean_numeric(df["Business Impact"], 0.50)
    df["Dependency Score"] = clean_numeric(df["Dependency Score"], 0.50)
    df["Downtime Cost"] = clean_numeric(df["Downtime Cost"], 1000.0).clip(lower=0)
    df["Est. Effort"] = clean_numeric(df["Est. Effort"], 1.0).clip(lower=0)

    df["Severity"] = df["Severity"].fillna("Medium").astype(str)
    df["Criticality"] = df["Criticality"].fillna("Medium").astype(str)
    df["Affected System"] = df["Affected System"].fillna("Unknown System").astype(str)

    blank_cve_mask = df["CVE ID"].isna() | (df["CVE ID"].astype(str).str.strip() == "")
    if blank_cve_mask.any():
        df.loc[blank_cve_mask, "CVE ID"] = [
            f"CVE-AUTO-{i+1:04d}" for i in range(blank_cve_mask.sum())
        ]
    df["CVE ID"] = df["CVE ID"].astype(str)

    severity_numeric = map_severity_to_numeric(df["Severity"])
    criticality_numeric = map_criticality_to_numeric(df["Criticality"])

    df["cvss_norm"] = df["CVSS Score"] / 10.0
    df["severity_norm"] = severity_numeric
    df["exploit_prob_norm"] = min_max_normalize(df["Exploit Prob (EPSS)"])
    df["business_impact_norm"] = min_max_normalize(df["Business Impact"])
    df["dependency_score_norm"] = min_max_normalize(df["Dependency Score"])
    df["downtime_cost_norm"] = min_max_normalize(df["Downtime Cost"])
    df["effort_norm"] = min_max_normalize(df["Est. Effort"])
    df["criticality_norm"] = criticality_numeric

    df["risk_score"] = (
        0.50 * df["cvss_norm"] +
        0.25 * df["severity_norm"] +
        0.15 * df["exploit_prob_norm"] +
        0.10 * df["criticality_norm"]
    ).clip(0, 1)

    return df


def score_dataframe(df: pd.DataFrame, risk_appetite: str) -> pd.DataFrame:
    df = df.copy()
    weights = get_weight_profile(risk_appetite)

    df["priority_score"] = (
        weights["risk"] * df["risk_score"] +
        weights["business"] * df["business_impact_norm"] +
        weights["dependency"] * df["dependency_score_norm"] +
        weights["exploit_bonus"] * df["exploit_prob_norm"] -
        weights["downtime_penalty"] * df["downtime_cost_norm"] -
        weights["effort_penalty"] * df["effort_norm"]
    ).clip(0, 1)

    df["priority_score"] = df["priority_score"].round(4)
    df["risk_score"] = df["risk_score"].round(4)

    df["recommended_action"] = df["priority_score"].apply(recommend_action)
    df["recommended_window"] = df.apply(
        lambda row: recommend_window(row["priority_score"], row["downtime_cost_norm"]),
        axis=1,
    )
    df["explanation"] = df.apply(build_explanation, axis=1)

    df = df.sort_values(
        by=["priority_score", "risk_score", "Exploit Prob (EPSS)"],
        ascending=[False, False, False],
    ).reset_index(drop=True)

    return df


def build_summary(df: pd.DataFrame, input_path: str, risk_appetite: str) -> Dict:
    top_items = df.head(5)[["CVE ID", "Affected System", "priority_score", "recommended_action"]]
    top_records = top_items.to_dict(orient="records")

    return {
        "input_file": input_path,
        "risk_appetite": risk_appetite,
        "total_vulnerabilities": int(len(df)),
        "top_priority_cve": str(df.iloc[0]["CVE ID"]) if len(df) else None,
        "top_priority_score": float(df.iloc[0]["priority_score"]) if len(df) else None,
        "immediate_patch_count": int((df["recommended_action"] == "Patch immediately").sum()),
        "next_window_count": int((df["recommended_action"] == "Patch in next maintenance window").sum()),
        "monitor_count": int((df["recommended_action"] == "Monitor for now").sum()),
        "top_recommendations": top_records,
    }


def save_outputs(
    df: pd.DataFrame,
    output_csv: str,
    summary_json: Optional[str],
    input_path: str,
    risk_appetite: str,
) -> None:
    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    export_df = df.copy()
    export_df["Priority Score"] = export_df["priority_score"]
    export_df["Risk Score"] = export_df["risk_score"]

    preferred_columns = [
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
        "Risk Score",
        "Priority Score",
        "recommended_action",
        "recommended_window",
        "explanation",
    ]

    existing_columns = [col for col in preferred_columns if col in export_df.columns]
    export_df[existing_columns].to_csv(output_path, index=False)

    if summary_json:
        summary_path = Path(summary_json)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary = build_summary(df, input_path, risk_appetite)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)


def main() -> None:
    args = parse_args()

    df = load_dataset(args.input)
    df = prepare_dataframe(df)
    df = apply_what_if(df, args.what_if_cve, args.what_if_exploit_prob)
    df = prepare_dataframe(df)
    df = score_dataframe(df, args.risk_appetite)

    save_outputs(
        df=df,
        output_csv=args.output,
        summary_json=args.summary_json,
        input_path=args.input,
        risk_appetite=args.risk_appetite,
    )

    print("\nAgentic Patch Strategist run complete.")
    print(f"Input file: {args.input}")
    print(f"Output CSV: {args.output}")
    if args.summary_json:
        print(f"Summary JSON: {args.summary_json}")

    print("\nTop 5 recommendations:")
    preview = df.head(5)[
        ["CVE ID", "Affected System", "priority_score", "recommended_action"]
    ]
    print(preview.to_string(index=False))


if __name__ == "__main__":
    main()