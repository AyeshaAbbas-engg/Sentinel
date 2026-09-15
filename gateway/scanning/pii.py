# ════════════════════════════════════════════════════════
# SENTINEL — PII Scanner  (v2: regex pre-filter + Presidio)
#
# Two-layer approach:
#   Layer A — fast local regex for high-recall PII patterns
#             (email, phone, SSN, credit card, IBAN, names in
#              medical context). Catches the 0/6 pii_leakage
#              benchmark gap when Presidio is unavailable or
#              misses due to confidence threshold.
#   Layer B — Presidio microservice for ML-based NER with
#             confidence gating (≥ 0.7). De-duplication
#             ensures a span is only reported once.
#
# Fail-closed behaviour is preserved: if BOTH layers fail the
# request is denied.
# ════════════════════════════════════════════════════════

import re
import time
import httpx
from fastapi import HTTPException
from context import RequestContext, Finding
from config import PRESIDIO_URL, PRESIDIO_TIMEOUT

CONFIDENCE_THRESHOLD = 0.7

# ── Circuit breaker (Presidio) ────────────────────────────
_failure_count = 0
_last_failure = 0.0
_FAILURE_THRESHOLD = 3
_RECOVERY_TIMEOUT = 30  # seconds


def _circuit_open() -> bool:
    global _failure_count, _last_failure
    if _failure_count >= _FAILURE_THRESHOLD:
        if time.time() - _last_failure < _RECOVERY_TIMEOUT:
            return True
        _failure_count = _FAILURE_THRESHOLD - 1
    return False


def _record_failure():
    global _failure_count, _last_failure
    _failure_count += 1
    _last_failure = time.time()


def _record_success():
    global _failure_count
    _failure_count = 0


# ── Layer A: local regex patterns ────────────────────────
# Each entry: (pattern, entity_type, severity, score_delta)
# Ordered from highest to lowest severity so first-match wins
# for overlapping spans (longest match preferred via sort below).

_REGEX_PII_PATTERNS = [
    # US Social Security Number  (e.g. 123-45-6789 or 123 45 6789)
    (r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b",
     "US_SSN", "critical", 0.5),

    # Credit card numbers — major card patterns with optional separators
    (r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))"
     r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
     "CREDIT_CARD", "critical", 0.5),

    # IBAN — starts with 2 letters, 2 digits, up to 30 alphanumeric
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
     "IBAN_CODE", "critical", 0.5),

    # Email address
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
     "EMAIL_ADDRESS", "high", 0.3),

    # US phone — various formats
    (r"(?:\+1[-\s]?)?(?:\(\d{3}\)|\d{3})[-\s]?\d{3}[-\s]?\d{4}\b",
     "PHONE_NUMBER", "high", 0.3),

    # International phone (starts with +, 7–15 digits)
    (r"\+\d{1,3}[-\s]?\d{3,5}[-\s]?\d{3,5}[-\s]?\d{2,5}\b",
     "PHONE_NUMBER", "high", 0.3),

    # Person name in medical / HR context:
    # "Patient record: <Name>" or "Contact <Name> at" etc.
    (r"(?i)(?:patient\s+record|contact|patient|employee)\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
     "PERSON", "high", 0.25),

    # Date of birth — ISO or US formats
    (r"\b(?:dob|date\s+of\s+birth|born)[:\s]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b",
     "DATE_OF_BIRTH", "high", 0.25),
    (r"\b(?:dob|date\s+of\s+birth|born)[:\s]+\d{4}-\d{2}-\d{2}\b",
     "DATE_OF_BIRTH", "high", 0.25),

    # Medical diagnosis disclosure keywords
    (r"(?i)\bdiagnosed\s+with\b",
     "MEDICAL_INFO", "high", 0.3),
]


def _severity(entity_type: str) -> str:
    if entity_type in {"US_SSN", "CREDIT_CARD", "IBAN_CODE"}:
        return "critical"
    if entity_type in {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "DATE_OF_BIRTH", "MEDICAL_INFO"}:
        return "high"
    return "medium"


def _score_delta(entity_type: str) -> float:
    if entity_type in {"US_SSN", "CREDIT_CARD", "IBAN_CODE"}:
        return 0.5
    if entity_type in {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "DATE_OF_BIRTH", "MEDICAL_INFO"}:
        return 0.3
    return 0.15


def _regex_scan(text: str) -> list[dict]:
    """
    Run all regex patterns and return a list of span dicts:
    {start, end, entity_type, matched_text}
    """
    spans = []
    for pattern, entity_type, _, __ in _REGEX_PII_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            spans.append({
                "start": m.start(),
                "end":   m.end(),
                "entity_type": entity_type,
                "matched_text": m.group(0),
                "source": "regex",
            })

    # Sort by length descending so longer (more specific) matches win
    spans.sort(key=lambda s: s["end"] - s["start"], reverse=True)

    # Remove overlapping spans (greedy longest-first)
    kept: list[dict] = []
    covered: set[int] = set()
    for span in spans:
        positions = set(range(span["start"], span["end"]))
        if not positions & covered:
            kept.append(span)
            covered |= positions

    return kept


def _redact(text: str, spans: list[dict]) -> str:
    """Replace each detected span with [ENTITY_TYPE] placeholder."""
    # Sort by start descending so replacements don't shift offsets
    for span in sorted(spans, key=lambda s: s["start"], reverse=True):
        text = text[:span["start"]] + f"[{span['entity_type']}]" + text[span["end"]:]
    return text


async def scan_pii(ctx: RequestContext) -> RequestContext:
    """
    Two-layer PII scan:
      1. Local regex (always runs, fast, high recall on structured PII)
      2. Presidio (ML-based, high precision on unstructured text)
    Fail-closed if Presidio is unavailable and regex found nothing
    suspicious enough to block — but findings from regex ARE preserved.
    """

    text = ctx.raw_prompt

    # ── Layer A: regex scan ──────────────────────────────
    regex_spans = _regex_scan(text)
    for span in regex_spans:
        etype = span["entity_type"]
        ctx.findings.append(Finding(
            scanner="pii",
            severity=_severity(etype),
            description=f"PII detected: {etype}",
            matched=span["matched_text"][:20],
            score_delta=_score_delta(etype),
        ))
    # ── Layer B: Presidio scan ───────────────────────────
    if not _circuit_open():
        try:
            async with httpx.AsyncClient(timeout=float(PRESIDIO_TIMEOUT)) as client:
                response = await client.post(
                    f"{PRESIDIO_URL}/analyze",
                    # Analyse original text so Presidio offsets always refer
                    # to the string later redacted.  Deduplication below
                    # prevents regex and Presidio from reporting a span twice.
                    json={"text": text, "language": "en"}
                )
                response.raise_for_status()
                entities = response.json()
            _record_success()

            confident = [e for e in entities if e["score"] >= CONFIDENCE_THRESHOLD]

            for entity in confident:
                etype = entity["entity_type"]
                start, end = entity["start"], entity["end"]
                if any(start < span["end"] and end > span["start"] for span in regex_spans):
                    continue
                ctx.findings.append(Finding(
                    scanner="pii",
                    severity=_severity(etype),
                    description=f"PII detected: {etype}",
                    matched=text[start:end][:20],
                    score_delta=_score_delta(etype),
                ))
                regex_spans.append({
                    "start": start,
                    "end":   end,
                    "entity_type": etype,
                    "matched_text": text[start:end],
                    "source": "presidio",
                })

        except Exception:
            _record_failure()
            # If Presidio is down but regex already found PII, continue.
            # If Presidio is down AND regex found nothing, fail-closed.
            if not regex_spans:
                raise HTTPException(
                    status_code=503,
                    detail="PII scanning failed — request denied (fail-closed)"
                )
    else:
        # Circuit open — regex findings still propagate
        if not regex_spans:
            raise HTTPException(
                status_code=503,
                detail="PII scanning service unavailable — request denied (fail-closed)"
            )

    # ── Redact clean_prompt from all confirmed spans ─────
    if regex_spans:
        ctx.clean_prompt = _redact(ctx.raw_prompt, regex_spans)
    else:
        ctx.clean_prompt = ctx.raw_prompt

    return ctx
