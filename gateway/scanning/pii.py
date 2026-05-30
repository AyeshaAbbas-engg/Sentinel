import time
import httpx
from fastapi import HTTPException
from context import RequestContext, Finding
from config import PRESIDIO_URL, PRESIDIO_TIMEOUT

CONFIDENCE_THRESHOLD = 0.7

# Circuit breaker state
_failure_count = 0
_last_failure = 0.0
_FAILURE_THRESHOLD = 3
_RECOVERY_TIMEOUT = 30  # seconds before retrying after circuit opens


def _circuit_open() -> bool:
    global _failure_count, _last_failure
    if _failure_count >= _FAILURE_THRESHOLD:
        if time.time() - _last_failure < _RECOVERY_TIMEOUT:
            return True
        # Half-open: allow one attempt
        _failure_count = _FAILURE_THRESHOLD - 1
    return False


def _record_failure():
    global _failure_count, _last_failure
    _failure_count += 1
    _last_failure = time.time()


def _record_success():
    global _failure_count
    _failure_count = 0


async def scan_pii(ctx: RequestContext) -> RequestContext:
    """Calls Presidio to detect PII. Fails closed if service is unavailable."""
    if _circuit_open():
        raise HTTPException(
            status_code=503,
            detail="PII scanning service unavailable — request denied (fail-closed)"
        )

    try:
        async with httpx.AsyncClient(timeout=float(PRESIDIO_TIMEOUT)) as client:
            response = await client.post(
                f"{PRESIDIO_URL}/analyze",
                json={"text": ctx.raw_prompt, "language": "en"}
            )
            response.raise_for_status()
            entities = response.json()
        _record_success()
    except Exception:
        _record_failure()
        raise HTTPException(
            status_code=503,
            detail="PII scanning failed — request denied (fail-closed)"
        )

    confident_entities = [e for e in entities if e["score"] >= CONFIDENCE_THRESHOLD]

    if not confident_entities:
        ctx.clean_prompt = ctx.raw_prompt
        return ctx

    clean_text = ctx.raw_prompt
    sorted_entities = sorted(confident_entities, key=lambda x: x["start"], reverse=True)

    for entity in sorted_entities:
        start, end = entity["start"], entity["end"]
        entity_type = entity["entity_type"]
        original_text = ctx.raw_prompt[start:end]
        clean_text = clean_text[:start] + f"[{entity_type}]" + clean_text[end:]
        ctx.findings.append(Finding(
            scanner="pii",
            severity=_get_severity(entity_type),
            description=f"PII detected: {entity_type}",
            matched=original_text[:20],
            score_delta=0.15
        ))

    ctx.clean_prompt = clean_text
    return ctx


def _get_severity(entity_type: str) -> str:
    if entity_type in ["US_SSN", "CREDIT_CARD", "IBAN_CODE"]:
        return "critical"
    if entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"]:
        return "high"
    return "medium"
