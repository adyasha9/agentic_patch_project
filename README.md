# Agentic Patch Strategist

Working prototype for the UMD Agentic AI Challenge.

## Files
- `agentic_patch_strategist.py` - main scoring engine
- `sample_data/Agentic_AI_Dataset.csv` - demo dataset
- `outputs/` - generated ranked plans and what-if results

## Run
```bash
python agentic_patch_strategist.py --input sample_data/Agentic_AI_Dataset.csv --output outputs/ranked_patch_plan.csv --summary-json outputs/summary.json
```

## What-if simulation
```bash
python agentic_patch_strategist.py --input sample_data/Agentic_AI_Dataset.csv --risk-appetite aggressive --what-if-cve CVE-2024-3400 --output outputs/what_if.csv --summary-json outputs/what_if_summary.json
```

## Logic
Priority Score = (Risk x Business Impact x Dependency Factor) / (Downtime Cost + Effort)

The prototype is business-aware because it uses:
- CVSS + EPSS-like exploit likelihood
- system criticality
- business impact
- dependency/cascade risk
- downtime and engineering effort
- risk appetite controls


## Streamlit demo UI
Run:
```bash
streamlit run streamlit_app.py
```

What it provides:
- upload CSV or Excel vulnerability data
- choose conservative, balanced, or aggressive risk appetite
- view ranked patch plan and explanations
- run a what-if exploit spike simulation
- download ranked CSV and summary JSON

## FastAPI server for n8n / webhook demos
Run:
```bash
uvicorn api_server:app --reload
```

Useful endpoints:
- `GET /health`
- `POST /rank` with JSON payload
- `POST /what-if` with JSON payload
- `POST /upload-rank` with multipart file upload

### Example JSON payload for `/rank`
```json
{
  "risk_appetite": "balanced",
  "records": [
    {
      "CVE ID": "CVE-2024-3400",
      "CVSS Score": 10.0,
      "Exploit Prob (EPSS)": 0.91,
      "Affected System": "Payment API",
      "Criticality": "Critical",
      "Business Impact": 250000,
      "Dependency Score": 1.8,
      "Downtime Cost": 30000,
      "Est. Effort": 2,
      "Regulatory": "High",
      "Customer Impact": "High"
    }
  ]
}
```

### Minimal n8n flow idea
1. Trigger: Manual Trigger or Webhook
2. HTTP Request node -> call `POST /rank`
3. Parse JSON response
4. Send top 3 recommendations to Slack, Gmail, or a dashboard

If you are running n8n locally and the API locally too, point the HTTP Request node to:
- `http://host.docker.internal:8000/rank` when n8n is in Docker
- `http://localhost:8000/rank` when both are on the same machine
