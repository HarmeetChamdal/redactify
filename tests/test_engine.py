"""Engine smoke tests -- regex-only, no spaCy model required."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine import RedactionEngine

CONFIG = {
    "default_behavior": "redact",
    "enable_ner": False,
    "enable_regex": True,
    "enabled_entity_types": ["PERSON", "EMAIL", "PHONE", "SSN"],
    "entity_behaviors": {"EMAIL": "partial_mask", "PHONE": "partial_mask", "SSN": "hash"},
    "hash_length": 12,
    "partial_mask_keep_chars": 2,
    "replacements": {"PERSON": "[NAME]"},
    "keep_audit": False,
}


def test_email_and_phone_redacted():
    engine = RedactionEngine(CONFIG)
    out, redactions = engine.redact(
        "Contact harmeetchamdal@gmail.com or (713) 597-9425."
    )
    assert "harmeetchamdal@gmail.com" not in out
    assert "713" not in out or "597-9425" not in out
    types = {r["entity_type"] for r in redactions}
    assert {"EMAIL", "PHONE"} <= types


def test_hash_behaviour():
    engine = RedactionEngine(CONFIG)
    out, _ = engine.redact("SSN 123-45-6789")
    assert "123-45-6789" not in out
    assert "[HASH:SSN:" in out


def test_override_redact():
    engine = RedactionEngine(CONFIG)
    out, _ = engine.redact("Email harmeetchamdal@gmail.com", behaviour="redact")
    assert out == "Email [REDACTED:EMAIL]"
