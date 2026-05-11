import json
import hashlib
from datetime import datetime, timezone
from context import RequestContext

def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:8]

def log_request(ctx: RequestContext):
    """
    Writes complete structured audit log for every request.
    """
    # Summarize findings by scanner
    pii_entities = [
        f.description for f in ctx.findings
        if f.scanner == "pii"
    ]
    injection_findings = [
        f.description for f in ctx.findings
        if f.scanner == "injection"
    ]
    secret_findings = [
        f.description for f in ctx.findings
        if f.scanner == "secret"
    ]

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": ctx.request_id,
        "user_id": ctx.user_id,
        "role": ctx.role,
        "raw_prompt_hash": hash_text(ctx.raw_prompt),
        "clean_prompt_hash": hash_text(ctx.clean_prompt),
        "pii_detected": len(pii_entities) > 0,
        "pii_entities": pii_entities,
        "injection_detected": len(injection_findings) > 0,
        "injection_findings": injection_findings,
        "output_flagged": len(secret_findings) > 0,
        "secret_findings": secret_findings,
        "risk_score": round(ctx.risk_score, 2),
        "policy_decision": ctx.policy_decision,
        "policy_reason": ctx.policy_reason,
        "model_used": ctx.model_used,
        "total_latency_ms": ctx.latency_ms,
    }

    print(json.dumps(log_entry))