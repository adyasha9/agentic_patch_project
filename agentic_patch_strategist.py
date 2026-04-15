#!/usr/bin/env python3
"""Agentic Patch Strategist - working prototype

Loads a vulnerability dataset, scores vulnerabilities using business-aware
prioritization logic, produces a ranked patch plan, and can run a what-if
exploit spike simulation.

Usage:
    python agentic_patch_strategist.py --input Agentic_AI_Dataset.csv --output ranked_plan.csv
    python agentic_patch_strategist.py --input Agentic_AI_Dataset.csv --risk-appetite aggressive --what-if-cve CVE-2024-3400
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd

DEFAULT_WEIGHTS = {
    "conservative": {"risk": 0.95, "business": 1.10, "dependency": 1.10, "downtime": 1.20, "effort": 1.10},
    "balanced":     {"risk": 1.00, "business": 1.00, "dependency": 1.00, "downtime": 1.00, "effort": 1.00},
    "aggressive":   {"risk": 1.15, "business": 1.10, "dependency": 1.05, "downtime": 0.85, "effort": 0.90},
}

SEVERITY_MAP = {"Low": 1.0, "Medium": 4.0, "High": 7.0, "Critical": 9.0}
CRITICALITY_MAP = {"Low": 1.0, "Medium": 1.25, "High": 1.6, "Critical": 2.0}
REGULATORY_MAP = {"None": 1.0, "Low": 1.1, "Medium": 1.2, "High": 1.35, "Critical": 1.5}
CUSTOMER_MAP = {"Low": 1.0, "Medium": 1.15, "High": 1.3, "Critical": 1.45}
ROLLBACK_MAP = {"Low": 1.0, "Medium": 1.1, "High": 1.25, "Critical": 1.4}
DOWNTIME_SENS_MAP = {"Low": 1.0, "Medium": 1.1, "High": 1.25, "Critical": 1.4}


def _read_input(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    if path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    raise ValueError("Supported input types: .csv, .xlsx, .xls")


def _normalize(df: pd.DataFrame) -> pd.DataFrame:
    rename = {
        "CVE ID": "cve_id",
        "CVSS Score": "cvss",
        "Severity": "severity",
        "Severity Label": "severity_label",
        "Exploit Prob (EPSS)": "epss",
        "Affected System": "affected_system",
        "Description": "description",
        "Criticality": "criticality",
        "System Criticality": "criticality",
        "Business Impact": "business_impact",
        "Dependency Score": "dependency_score",
        "Downtime Cost": "downtime_cost",
        "Est. Effort": "effort",
        "Effort": "effort",
        "Regulatory": "regulatory",
        "Customer Impact": "customer_impact",
        "Maintenance Window": "maintenance_window",
        "Rollback Risk": "rollback_risk",
        "Downtime Sensitivity": "downtime_sensitivity",
        "Cascade Risk": "cascade_risk",
    }
    df = df.rename(columns=rename).copy()

    # Fill missing columns with sensible defaults for compressed demo inputs.
    defaults = {
        "cvss": None,
        "severity_label": None,
        "criticality": "Medium",
        "business_impact": 50000,
        "dependency_score": 1.0,
        "downtime_cost": 10000,
        "effort": 1.0,
        "regulatory": "Low",
        "customer_impact": "Medium",
        "maintenance_window": "Next planned window",
        "rollback_risk": "Medium",
        "downtime_sensitivity": "Medium",
        "cascade_risk": 1.0,
    }
    for col, val in defaults.items():
        if col not in df.columns:
            df[col] = val

    if df["cvss"].isna().all() and "severity" in df.columns:
        df["cvss"] = df["severity"].map(SEVERITY_MAP)
    if df["severity_label"].isna().all() and "severity" in df.columns:
        df["severity_label"] = df["severity"]
    if df["severity_label"].isna().any():
        df["severity_label"] = df["severity_label"].fillna("Medium")
    if df["cvss"].isna().any():
        df["cvss"] = df["cvss"].fillna(df["severity_label"].map(SEVERITY_MAP)).fillna(5.0)

    numeric_cols = ["cvss", "epss", "business_impact", "dependency_score", "downtime_cost", "effort", "cascade_risk"]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    return df


def _calc_scores(df: pd.DataFrame, risk_appetite: str) -> pd.DataFrame:
    weights = DEFAULT_WEIGHTS[risk_appetite]
    out = df.copy()

    out["risk_score"] = (out["cvss"] / 10.0) * (1.0 + out["epss"]).clip(lower=0.2)
    out["criticality_multiplier"] = out["criticality"].map(CRITICALITY_MAP).fillna(1.25)
    out["regulatory_multiplier"] = out["regulatory"].map(REGULATORY_MAP).fillna(1.1)
    out["customer_multiplier"] = out["customer_impact"].map(CUSTOMER_MAP).fillna(1.15)
    out["rollback_multiplier"] = out["rollback_risk"].map(ROLLBACK_MAP).fillna(1.1)
    out["downtime_sensitivity_multiplier"] = out["downtime_sensitivity"].map(DOWNTIME_SENS_MAP).fillna(1.1)

    out["business_score"] = (
        out["business_impact"].clip(lower=1) / 100000.0
        * out["criticality_multiplier"]
        * out["regulatory_multiplier"]
        * out["customer_multiplier"]
    )

    out["dependency_factor"] = out[["dependency_score", "cascade_risk"]].max(axis=1).clip(lower=0.5)
    out["disruption_cost"] = (
        out["downtime_cost"].clip(lower=1) / 10000.0
        * out["rollback_multiplier"]
        * out["downtime_sensitivity_multiplier"]
    ) + out["effort"].clip(lower=0.25)

    out["priority_score"] = (
        out["risk_score"] * weights["risk"]
        * out["business_score"] * weights["business"]
        * out["dependency_factor"] * weights["dependency"]
    ) / (
        out["disruption_cost"] * weights["downtime"]
        + out["effort"].clip(lower=0.25) * weights["effort"]
    ) * 100

    out["expected_loss"] = (
        out["risk_score"] * out["business_impact"].clip(lower=1) * out["dependency_factor"]
    ).round(2)

    out = out.sort_values("priority_score", ascending=False).reset_index(drop=True)
    out["recommended_action"] = out.apply(_recommend_action, axis=1)
    out["recommended_patch_window"] = out.apply(_recommend_window, axis=1)
    out["explanation"] = out.apply(_explain, axis=1)
    return out


def _recommend_action(row: pd.Series) -> str:
    if row["priority_score"] >= 0.6:
        return "Patch immediately"
    if row["priority_score"] >= 0.25:
        return "Patch in next maintenance window"
    return "Monitor and defer with controls"


def _recommend_window(row: pd.Series) -> str:
    if row["recommended_action"] == "Patch immediately":
        return "Emergency/24h window"
    if row["criticality"] in {"High", "Critical"}:
        return "Weekend or low-traffic approved window"
    return str(row.get("maintenance_window", "Next planned window"))


def _explain(row: pd.Series) -> str:
    return (
        f"{row['cve_id']} is prioritized for {row['affected_system']} because it combines "
        f"CVSS {row['cvss']:.1f}, exploit probability {row['epss']:.2f}, "
        f"{row['criticality']} system criticality, and dependency factor {row['dependency_factor']:.2f}. "
        f"Recommended action: {row['recommended_action']}."
    )


def run_what_if(df: pd.DataFrame, cve_id: str, epss_increase: float, risk_appetite: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    baseline = _calc_scores(df, risk_appetite)
    scenario = df.copy()
    mask = scenario["cve_id"].astype(str).str.lower() == cve_id.lower()
    if not mask.any():
        raise ValueError(f"CVE not found in dataset: {cve_id}")
    scenario.loc[mask, "epss"] = (scenario.loc[mask, "epss"] + epss_increase).clip(upper=1.0)
    scenario_ranked = _calc_scores(scenario, risk_appetite)
    merged = baseline[["cve_id", "priority_score"]].merge(
        scenario_ranked[["cve_id", "priority_score"]], on="cve_id", suffixes=("_baseline", "_scenario")
    )
    merged["score_delta"] = merged["priority_score_scenario"] - merged["priority_score_baseline"]
    return baseline, scenario_ranked.merge(merged[["cve_id", "score_delta"]], on="cve_id")


def build_summary(df: pd.DataFrame, top_n: int = 5) -> Dict[str, object]:
    top = df.head(top_n)
    return {
        "records": len(df),
        "top_recommendations": top[["cve_id", "affected_system", "priority_score", "recommended_action"]]
            .round({"priority_score": 3}).to_dict(orient="records"),
        "total_expected_loss": float(df["expected_loss"].sum()),
        "systems_covered": sorted(df["affected_system"].dropna().astype(str).unique().tolist()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic Patch Strategist")
    parser.add_argument("--input", required=True, help="Path to input CSV/XLSX")
    parser.add_argument("--output", default="ranked_patch_plan.csv", help="Output CSV path")
    parser.add_argument("--summary-json", default="summary.json", help="Output summary JSON path")
    parser.add_argument("--risk-appetite", choices=sorted(DEFAULT_WEIGHTS), default="balanced")
    parser.add_argument("--what-if-cve", help="CVE ID for exploit spike simulation")
    parser.add_argument("--epss-increase", type=float, default=0.25, help="Increase to EPSS in what-if run")
    args = parser.parse_args()

    raw = _read_input(Path(args.input))
    normalized = _normalize(raw)

    if args.what_if_cve:
        baseline, scenario = run_what_if(normalized, args.what_if_cve, args.epss_increase, args.risk_appetite)
        baseline.to_csv(Path(args.output).with_stem(Path(args.output).stem + "_baseline"), index=False)
        scenario.to_csv(Path(args.output).with_stem(Path(args.output).stem + "_scenario"), index=False)
        summary = {
            "baseline": build_summary(baseline),
            "scenario": build_summary(scenario),
            "what_if_cve": args.what_if_cve,
            "epss_increase": args.epss_increase,
        }
    else:
        ranked = _calc_scores(normalized, args.risk_appetite)
        ranked.to_csv(args.output, index=False)
        summary = build_summary(ranked)

    with open(args.summary_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
