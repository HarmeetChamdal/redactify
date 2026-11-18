# Redactify

A Python / FastAPI PII redaction service: regex + spaCy NER redaction,
a config-driven engine, an SQLite audit trail, a REST API, and a small
HTML/JS frontend.

**Scope — please read:** this is an academic / personal project rebuilt
from the author's resume description. It is not a production system,
has not been deployed, and no accuracy, latency, or throughput numbers
are claimed here — none were measured. Do not use it to redact real
sensitive documents without a proper review: regex and a small spaCy
model will miss things, and the audit log is a local SQLite file.

## What it does

- `POST /redact` — redacts PII from submitted text and returns the
  redacted text plus a per-entity-type summary (type, count, behaviour).
- `GET /health` — service status, including whether spaCy NER loaded.
- `GET /audit` — recent audit entries (timestamp, entity type, count,
  behaviour). Raw PII is never written to the audit log.
- `GET /` — a simple frontend page to try redaction in the browser.

## Tech used

Python, FastAPI, Uvicorn, spaCy (`en_core_web_sm`), Pydantic, SQLite,
plain HTML/JS frontend. See `requirements.txt`.

## Config-driven engine (`config.json`)

Five processing behaviours, chosen per entity type in `config.json`
(or overridden per request with the `behaviour` field):

| Behaviour | Result |
|---|---|
| `redact` | `[REDACTED:TYPE]` |
| `replace` | configured placeholder, e.g. `[NAME]` |
| `mask` | every character replaced with `*` |
| `hash` | `[HASH:TYPE:<first 12 chars of SHA-256>]` |
| `partial_mask` | keep first/last characters, mask the middle (e.g. `ha***@gmail.com`) |

Other toggles in `config.json`: `enable_ner`, `enable_regex`,
`enabled_entity_types`, `default_behavior`, `keep_audit`
(whether redaction summaries are written to the audit log).

Detection: regex for EMAIL, PHONE, SSN, CREDIT_CARD, DATE; spaCy NER
for PERSON, ORG, GPE, DATE. If the spaCy model is not installed, the
engine falls back to regex-only and `GET /health` reports
`ner_available: false`.

## How to run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm   # optional; regex-only without it
uvicorn app.main:app --reload --port 8000
```

Then open http://127.0.0.1:8000/ or:

```bash
curl http://127.0.0.1:8000/health

curl -X POST http://127.0.0.1:8000/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Hi, I am Harmeet Singh Chamdal. Reach me at harmeetchamdal@gmail.com or (713) 597-9425."}'

curl http://127.0.0.1:8000/audit
```

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
# (pytest not in requirements.txt; install it separately if wanted,
#  or run the checks with plain python -m unittest-style imports.)
```

## Project layout

```
redactify/
├── app/
│   ├── main.py      # FastAPI app: /redact, /health, /audit, /
│   ├── engine.py    # regex + spaCy NER engine, 5 behaviours
│   └── audit.py     # SQLite audit trail (metadata only, no raw PII)
├── static/index.html
├── tests/test_engine.py
├── config.json
├── requirements.txt
└── README.md
```

## Author

Harmeet Singh Chamdal — B.S. Computer Science, Texas Tech University,
Dec 2025. Built from the Redactify project description on his resume
(Python, FastAPI, REST, spaCy, SQL, React — here the frontend is plain
HTML/JS served by FastAPI for simplicity).
