from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Optional

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.append(str(CURRENT_DIR))

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse

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

app = FastAPI(title="Agentic Patch Strategist API")


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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/upload-rank")
async def upload_rank(
    file: UploadFile = File(...),
    risk_appetite: str = Form("balanced"),
    what_if_cve: Optional[str] = Form(None),
    what_if_exploit_prob: float = Form(0.98),
    what_if_delay: Optional[str] = Form(None),
    delay_days: int = Form(30),
    schedule_start: Optional[str] = Form(None),
    window_days: int = Form(7),
):
    try:
        suffix = Path(file.filename).suffix.lower()
        if suffix not in {".csv", ".xlsx", ".xls"}:
            return JSONResponse(
                status_code=400,
                content={"error": "Unsupported file type. Please upload CSV or XLSX."},
            )

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            contents = await file.read()
            tmp.write(contents)
            temp_path = tmp.name

        df = run_pipeline(
            input_source=temp_path,
            risk_appetite=risk_appetite,
            what_if_cve=what_if_cve,
            what_if_exploit_prob=what_if_exploit_prob,
            what_if_delay=what_if_delay,
            delay_days=delay_days,
            schedule_start=schedule_start,
            window_days=window_days,
        )

        summary = build_summary(df, file.filename, risk_appetite)

        preview_columns = [
            "CVE ID",
            "Affected System",
            "CVSS Score",
            "Severity",
            "Exploit Prob (EPSS)",
            "priority_score",
            "risk_tier",
            "recommended_action",
            "recommended_window",
            "scheduled_date",
            "schedule_slot",
            "scheduling_conflict",
            "detected_compliance",
            "what_if_note",
            "explanation",
        ]
        preview_columns = [col for col in preview_columns if col in df.columns]

        return {
            "summary": summary,
            "rows": df[preview_columns].to_dict(orient="records"),
        }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )