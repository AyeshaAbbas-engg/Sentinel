import os
import httpx
from typing import List
from context import RequestContext, Finding

PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://presidio:8001")
CONFIDENCE_THRESHOLD = 0.7

async def scan_pii(ctx: RequestContext) -> RequestContext:
    """
    Calls Presidio to detect PII in the prompt.
    Builds clean_prompt by replacing PII with typed tokens.
    Adds findings — risk score computed separately by risk.py
    """

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{PRESIDIO_URL}/analyze",
                json={"text": ctx.raw_prompt, "language": "en"}
            )
            entities = response.json()
    except Exception as e:
        print(f"PII scan failed: {e}")
        return ctx

    confident_entities = [
        e for e in entities
        if e["score"] >= CONFIDENCE_THRESHOLD
    ]

    if not confident_entities:
        ctx.clean_prompt = ctx.raw_prompt
        return ctx

    clean_text = ctx.raw_prompt

    sorted_entities = sorted(
        confident_entities,
        key=lambda x: x["start"],
        reverse=True
    )

    for entity in sorted_entities:
        start = entity["start"]
        end = entity["end"]
        entity_type = entity["entity_type"]
        original_text = ctx.raw_prompt[start:end]

        clean_text = clean_text[:start] + f"[{entity_type}]" + clean_text[end:]

        finding = Finding(
            scanner="pii",
            severity=get_severity(entity_type),
            description=f"PII detected: {entity_type}",
            matched=original_text[:20],
            score_delta=0.15  # risk.py will sum these up
        )
        ctx.findings.append(finding)

    ctx.clean_prompt = clean_text
    # NOTE: risk_score NOT updated here — risk.py does it
    return ctx


def get_severity(entity_type: str) -> str:
    critical = ["US_SSN", "CREDIT_CARD", "IBAN_CODE"]
    high = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"]
    medium = ["IP_ADDRESS", "LOCATION"]

    if entity_type in critical:
        return "critical"
    elif entity_type in high:
        return "high"
    else:
        return "medium"