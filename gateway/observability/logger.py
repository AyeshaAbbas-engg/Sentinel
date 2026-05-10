import json
import hashlib
from datetime import datetime,timezone
from context import RequestContext

def hash_text(text:str)-> str:
    return "sha256:"+hashlib.sha256(text.encode()).hexdigest()[:8]

def log_request(ctx:RequestContext):
    log_entry={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id":ctx.request_id,
        "user_id": ctx.user_id,
        "role": ctx.role,
        "raw_prompt_hash": hash_text(ctx.raw_prompt),
        "risk_score": ctx.risk_score,
        "policy_decision": ctx.policy_decision,
        "model_used": ctx.model_used,
        "total_latency_ms": ctx.latency_ms,
    }
    print(json.dumps(log_entry))