# SOC Copilot

An AI-assisted alert triage dashboard for a Security Operations Center. Every alert is
scored two ways — a deterministic rule-based baseline, and an LLM (Gemini) that reads
the raw log and returns a severity rating, false-positive judgment, reasoning, and a
recommended next action. The dashboard shows both side by side.

## Stack

- **Backend:** Python, FastAPI, SQLAlchemy, SQLite
- **AI triage:** Gemini API (`gemini-3.6-flash`)
- **Frontend:** vanilla HTML/CSS/JS (no build step, no framework)

## Setup

### 1. Backend

```bash
cd backend
pip install fastapi uvicorn sqlalchemy pydantic requests


export GEMINI_API_KEY="your-key-here"        # Mac/Linux
set GEMINI_API_KEY=your-key-here             # Windows cmd

python seed_data.py          # populates soc_copilot.db with 25 sample alerts
uvicorn main:app --reload --port 8000
```

API docs (for testing endpoints directly): http://localhost:8000/docs

### 2. Frontend

Just open `frontend/index.html` in a browser, or serve it so `fetch()` behaves
consistently:

```bash
cd frontend
python3 -m http.server 5500
```

Then visit http://localhost:5500

## How it works

1. `seed_data.py` loads 25 synthetic alerts (brute force, port scans, malware beacons,
   DDoS, exfiltration attempts, and a handful of genuine false positives) into SQLite.
2. Click an alert in the dashboard, then **Run AI Triage** — or **Run Triage on All**
   to triage everything at once.
3. Each alert gets triaged twice: `rule_engine.py` (instant, keyword-based) and
   `llm_triage.py` (Gemini call, returns severity + reasoning + recommended action).
4. The `/stats` endpoint computes a rule-vs-AI agreement rate and severity breakdown —
   this is the number to put in a "Findings" section later if you decide to add one.

## Project structure

```
soc-copilot/
├── backend/
│   ├── main.py           FastAPI app + routes
│   ├── models.py         SQLAlchemy models (Alert, Incident)
│   ├── schemas.py        Pydantic request/response schemas
│   ├── database.py       DB engine/session setup
│   ├── rule_engine.py    Rule-based triage baseline
│   ├── llm_triage.py     Gemini-based triage
│   └── seed_data.py      Synthetic alert generator
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

## Stretch features (not built yet, schema already supports them)

- **Alert correlation:** group related alerts into an `Incident` (the `Incident` model
  and `alert.incident_id` foreign key already exist — just needs the grouping logic
  and an LLM-generated incident summary)
- **MITRE ATT&CK tagging:** add a `mitre_technique` column, ask the LLM to classify
  against a short list of common techniques in the same triage prompt
- **PDF incident report export:** you already have DomPDF experience from ReconBoard —
  a Python equivalent (`weasyprint` or `reportlab`) would do the same job here
- **Slack webhook** on Critical-severity triage results
