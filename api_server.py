from __future__ import annotations

import io
from typing import Literal, Optional

import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from agentic_patch_strategist import _calc_scores, _normalize, build_summary, run_what_if

app = FastAPI(title="Agentic Patch Strategist API", version="1.0.0")

RiskAppetite = Literal["conservative", "balanced", "aggressive"]


class RankRequest(BaseModel):
    records: list[dict] = Field(..., description="List of vulnerability records")
    risk_appetite: RiskAppetite = "balanced"


class WhatIfRequest(BaseModel):
    records: list[dict]
    cve_id: str
    epss_increase: float = 0.25
    risk_appetite: RiskAppetite = "balanced"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/rank")
def rank_payload(req: RankRequest) -> dict:
    try:
        df = _normalize(pd.DataFrame(req.records))
        ranked = _calc_scores(df, req.risk_appetite)
        return {
            "summary": build_summary(ranked),
            "ranked_records": ranked.round({"priority_score": 6, "expected_loss": 2}).to_dict(orient="records"),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/what-if")
def what_if_payload(req: WhatIfRequest) -> dict:
    try:
        df = _normalize(pd.DataFrame(req.records))
        baseline, scenario = run_what_if(df, req.cve_id, req.epss_increase, req.risk_appetite)
        return {
            "baseline_summary": build_summary(baseline),
            "scenario_summary": build_summary(scenario),
            "baseline_records": baseline.round({"priority_score": 6, "expected_loss": 2}).to_dict(orient="records"),
            "scenario_records": scenario.round({"priority_score": 6, "expected_loss": 2}).to_dict(orient="records"),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/upload-rank")
async def upload_rank(
    file: UploadFile = File(...),
    risk_appetite: RiskAppetite = Form("balanced"),
) -> dict:
    try:
        content = await file.read()
        suffix = file.filename.lower().split(".")[-1]
        if suffix == "csv":
            df = pd.read_csv(io.BytesIO(content))
        elif suffix in {"xlsx", "xls"}:
            df = pd.read_excel(io.BytesIO(content))
        else:
            raise ValueError("Supported upload types are csv, xlsx, xls")
        ranked = _calc_scores(_normalize(df), risk_appetite)
        return {
            "summary": build_summary(ranked),
            "ranked_records": ranked.round({"priority_score": 6, "expected_loss": 2}).to_dict(orient="records"),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
