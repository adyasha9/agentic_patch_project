from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Optional

import pandas as pd
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse

from agentic_patch_strategist import (
    build_summary,
    load_dataset,
    prepare_dataframe,
    apply_what_if,
    score_dataframe,
)

app = FastAPI(title="Agentic Patch Strategist API")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/rank")
def rank_data(
    risk_appetite: str = Form("balanced"),
):
    return {
        "message": "Use /upload-rank to upload a CSV/XLSX file, or extend this endpoint for JSON payloads."
    }


@app.post("/what-if")
def what_if_data(
    risk_appetite: str = Form("balanced"),
    what_if_cve: str = Form(...),
    what_if_exploit_prob: float = Form(0.98),
):
    return {
        "message": "Use /upload-rank with what-if parameters and a file upload."
    }


@app.post("/upload-rank")
async def upload_rank(
    file: UploadFile = File(...),
    risk_appetite: str = Form("balanced"),
    what_if_cve: Optional[str] = Form(None),
    what_if_exploit_prob: float = Form(0.98),
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

        df = load_dataset(temp_path)
        df = prepare_dataframe(df)

        if what_if_cve:
            df = apply_what_if(df, what_if_cve, what_if_exploit_prob)
            df = prepare_dataframe(df)

        df = score_dataframe(df, risk_appetite)

        summary = build_summary(
            df=df,
            input_path=file.filename,
            risk_appetite=risk_appetite,
        )

        preview_columns = [
            "CVE ID",
            "Affected System",
            "CVSS Score",
            "Severity",
            "Exploit Prob (EPSS)",
            "priority_score",
            "recommended_action",
            "recommended_window",
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