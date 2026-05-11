import os
import httpx
from typing import List
from context import RequestContext, Finding

PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://presidio:8001")
CONFIDENCE_THRESHOLD = 0.7  # ignore detections below this

async def scan_pii(ctx: RequestContext) -> RequestContext:
    """
    Calls Presidio to detect PII in the prompt.
    Builds clean_prompt by replacing PII with typed tokens.
    Updates risk_score and findings.
    """

    # Step 1 — Call Presidio microservice
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{PRESIDIO_URL}/analyze",
                json={
                    "text": ctx.raw_prompt,
                    "language": "en"
                }
            )
            entities = response.json()
    except Exception as e:
        # If Presidio is down — log and continue without PII scan
        print(f"PII scan failed: {e}")
        return ctx

    # Step 2 — Filter by confidence threshold
    confident_entities = [
        e for e in entities
        if e["score"] >= CONFIDENCE_THRESHOLD
    ]

    if not confident_entities:
        # No PII found — clean prompt = raw prompt
        ctx.clean_prompt = ctx.raw_prompt
        return ctx

    # Step 3 — Build clean prompt using reverse replacement
    clean_text = ctx.raw_prompt

    # Sort by start position DESCENDING (right to left)
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

        # Replace with typed token
        clean_text = clean_text[:start] + f"[{entity_type}]" + clean_text[end:]

        # Create a Finding object for this detection
        finding = Finding(
            scanner="pii",
            severity=get_severity(entity_type),
            description=f"PII detected: {entity_type}",
            matched=original_text[:20],  # truncate for privacy
            score_delta=0.15
        )
        ctx.findings.append(finding)

    # Step 4 — Update context
    ctx.clean_prompt = clean_text

    # Step 5 — Update risk score (capped at 0.6 for PII scanner)
    pii_score = min(0.6, len(confident_entities) * 0.15)
    ctx.risk_score = min(1.0, ctx.risk_score + pii_score)

    return ctx


def get_severity(entity_type: str) -> str:
    """Map entity type to severity level"""
    critical = ["US_SSN", "CREDIT_CARD", "IBAN_CODE"]
    high = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"]
    medium = ["IP_ADDRESS", "LOCATION"]

    if entity_type in critical:
        return "critical"
    elif entity_type in high:
        return "high"
    else:
        return "medium"