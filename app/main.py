"""Redactify -- FastAPI PII redaction service (regex + spaCy NER)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.audit import get_audit, init_db, log_redactions
from app.engine import BEHAVIOURS, RedactionEngine, load_config

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG = load_config(BASE_DIR / "config.json")
ENGINE = RedactionEngine(CONFIG)
DB = init_db(BASE_DIR / CONFIG.get("audit_db_path", "audit.db"))

app = FastAPI(title="Redactify", version="0.1.0")


class RedactRequest(BaseModel):
    text: str = Field(..., min_length=1)
    behaviour: str | None = Field(
        default=None,
        description=f"Override for all entities: one of {sorted(BEHAVIOURS)}",
    )
    entity_types: list[str] | None = None


class RedactResponse(BaseModel):
    original_length: int
    redacted_text: str
    redactions: list[dict]
    ner_available: bool
    audit_logged: bool


@app.get("/health")
def health():
    return {
        "status": "ok",
        "ner_available": ENGINE.ner_available,
        "enable_regex": CONFIG.get("enable_regex", True),
        "enable_ner": CONFIG.get("enable_ner", True),
        "keep_audit": CONFIG.get("keep_audit", True),
        "default_behavior": CONFIG.get("default_behavior", "redact"),
    }


@app.post("/redact", response_model=RedactResponse)
def redact(req: RedactRequest):
    redacted_text, redactions = ENGINE.redact(
        req.text, behaviour=req.behaviour, entity_types=req.entity_types
    )
    audit_logged = False
    if CONFIG.get("keep_audit", True) and redactions:
        log_redactions(DB, redactions)
        audit_logged = True
    return RedactResponse(
        original_length=len(req.text),
        redacted_text=redacted_text,
        redactions=redactions,
        ner_available=ENGINE.ner_available,
        audit_logged=audit_logged,
    )


@app.get("/audit")
def audit(limit: int = Query(100, ge=1, le=1000)):
    return {"entries": get_audit(DB, limit=limit)}


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")
