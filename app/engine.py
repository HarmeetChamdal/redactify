"""Config-driven PII redaction engine: regex + spaCy NER.

Five processing behaviours, selected per entity type in config.json
(or overridden per request):
  1. redact       -> [REDACTED:TYPE]
  2. replace      -> a configured placeholder, e.g. [NAME]
  3. mask         -> every character replaced with '*'
  4. hash         -> [HASH:TYPE: first N chars of SHA-256]
  5. partial_mask -> keep the first/last few characters, mask the middle
                     (e.g. jo***@example.com, (713) ***-**42)

spaCy NER is optional: if the model is not installed the engine
falls back to regex-only and reports ner_available=False.
No raw PII is ever written to the audit log -- only entity type,
count and behaviour.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional

# Regex patterns for structured PII. Order matters: more specific first.
REGEX_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "PHONE": re.compile(
        r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}"
    ),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    # A bare 4-digit year is not PII on its own; dates need month/day context.
    "DATE": re.compile(
        r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b"
    ),
}

# spaCy labels we treat as PII / sensitive when NER is enabled.
NER_LABELS = {"PERSON", "ORG", "GPE", "DATE"}

BEHAVIOURS = {"redact", "replace", "mask", "hash", "partial_mask"}


def load_config(path: str | Path = "config.json") -> dict:
    p = Path(path)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


def _apply_behaviour(value: str, entity_type: str, behaviour: str, config: dict) -> str:
    if behaviour == "redact":
        return f"[REDACTED:{entity_type}]"
    if behaviour == "replace":
        replacements = config.get("replacements", {})
        return replacements.get(entity_type, f"[{entity_type}]")
    if behaviour == "mask":
        return "*" * len(value)
    if behaviour == "hash":
        length = int(config.get("hash_length", 12))
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]
        return f"[HASH:{entity_type}:{digest}]"
    if behaviour == "partial_mask":
        keep = int(config.get("partial_mask_keep_chars", 2))
        if len(value) <= keep * 2:
            return "*" * len(value)
        if entity_type == "EMAIL" and "@" in value:
            local, domain = value.split("@", 1)
            masked_local = local[:keep] + "*" * max(1, len(local) - keep)
            return f"{masked_local}@{domain}"
        if entity_type == "PHONE":
            digits = "".join(c for c in value if c.isdigit())
            if len(digits) >= 4:
                return f"***-***-{digits[-4:]}"
        return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]
    return f"[REDACTED:{entity_type}]"


class RedactionEngine:
    def __init__(self, config: Optional[dict] = None, config_path: str | Path = "config.json"):
        self.config = config if config is not None else load_config(config_path)
        self.nlp = None
        self.ner_available = False
        if self.config.get("enable_ner", True):
            try:
                import spacy

                self.nlp = spacy.load("en_core_web_sm")
                self.ner_available = True
            except Exception:
                # Graceful fallback: regex-only mode.
                self.nlp = None
                self.ner_available = False

    def _behaviour_for(self, entity_type: str, override: Optional[str]) -> str:
        if override and override in BEHAVIOURS:
            return override
        per_entity = self.config.get("entity_behaviors", {})
        behaviour = per_entity.get(entity_type, self.config.get("default_behavior", "redact"))
        return behaviour if behaviour in BEHAVIOURS else "redact"

    def redact(
        self,
        text: str,
        behaviour: Optional[str] = None,
        entity_types: Optional[list[str]] = None,
    ) -> tuple[str, list[dict]]:
        """Return (redacted_text, redactions).

        redactions: [{entity_type, count, behaviour}] -- no raw values.
        Spans are collected first and applied right-to-left so offsets
        stay valid; regex matches win over overlapping NER spans.
        """
        enabled = set(entity_types) if entity_types else set(
            self.config.get("enabled_entity_types", [])
        )
        spans: list[tuple[int, int, str]] = []  # (start, end, entity_type)

        def _overlaps(start: int, end: int) -> bool:
            return any(start < e and s < end for s, e, _ in spans)

        if self.config.get("enable_regex", True):
            for entity_type, pattern in REGEX_PATTERNS.items():
                if entity_type not in enabled:
                    continue
                for m in pattern.finditer(text):
                    if not _overlaps(m.start(), m.end()):
                        spans.append((m.start(), m.end(), entity_type))

        if self.nlp is not None:
            for ent in self.nlp(text).ents:
                if ent.label_ not in NER_LABELS or ent.label_ not in enabled:
                    continue
                if not _overlaps(ent.start_char, ent.end_char):
                    spans.append((ent.start_char, ent.end_char, ent.label_))

        spans.sort(key=lambda s: s[0], reverse=True)
        counts: dict[str, int] = {}
        behaviours: dict[str, str] = {}
        result = text
        for start, end, entity_type in spans:
            b = self._behaviour_for(entity_type, behaviour)
            result = result[:start] + _apply_behaviour(
                result[start:end], entity_type, b, self.config
            ) + result[end:]
            counts[entity_type] = counts.get(entity_type, 0) + 1
            behaviours[entity_type] = b

        redactions = [
            {"entity_type": t, "count": c, "behaviour": behaviours[t]}
            for t, c in sorted(counts.items())
        ]
        return result, redactions
