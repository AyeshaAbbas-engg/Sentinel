import os
import json
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from context import RequestContext
from config import LOG_DIR, LOG_MAX_BYTES, LOG_BACKUP_COUNT

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Set up rotating file logger
_audit_logger = logging.getLogger("sentinel.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False

_file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "audit.jsonl"),
    maxBytes=LOG_MAX_BYTES,
    backupCount=LOG_BACKUP_COUNT,
)
_file_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_file_handler)

# Also keep stdout for container log aggregation
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_stream_handler)


def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:8]


def log_request(ctx: RequestContext):
    pii_entities = [f.description for f in ctx.findings if f.scanner == "pii"]
    injection_findings = [f.description for f in ctx.findings if f.scanner == "injection"]
    secret_findings = [f.description for f in ctx.findings if f.scanner == "secret"]

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": ctx.request_id,
        "user_id": ctx.user_id,
        "role": ctx.role,
        "raw_prompt_hash": hash_text(ctx.raw_prompt),
        "clean_prompt_hash": hash_text(ctx.clean_prompt),
        "prompt_length": len(ctx.raw_prompt),
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

    _audit_logger.info(json.dumps(log_entry))
