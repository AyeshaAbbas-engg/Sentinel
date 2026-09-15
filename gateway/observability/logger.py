# ════════════════════════════════════════════════════════
# SENTINEL — Audit Logger  (v2: per-hop timings + cost)
#
# Emits one JSONL record per request to gateway/logs/audit.jsonl
# plus stdout for container log aggregation.
#
# New fields in v2:
#   hop_timings          list of {name, latency_ms, model?,
#                                 input_tokens, output_tokens,
#                                 estimated_cost_usd, status}
#   complexity_tier      classifier output
#   intent_class         classifier output
#   input_tokens         estimated tokens sent to LLM
#   output_tokens        estimated tokens received from LLM
#   estimated_cost_usd   estimated cost for this request
#
# Privacy: raw prompts are NOT logged — only SHA-256 prefix
# hashes, lengths, and structured findings.
# ════════════════════════════════════════════════════════

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

# Rotating JSONL file
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

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_stream_handler)


def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:8]


def log_request(ctx: RequestContext) -> None:
    """Emit one structured JSONL record for this request."""
    pii_entities       = [f.description for f in ctx.findings if f.scanner == "pii"]
    injection_findings = [f.description for f in ctx.findings if f.scanner == "injection"]
    secret_findings    = [f.description for f in ctx.findings if f.scanner == "secret"]

    # Serialise per-hop timing breakdown
    hops_serialised = [
        {
            "name":               h.name,
            "latency_ms":         h.latency_ms,
            **({"model": h.model} if h.model else {}),
            "input_tokens":       h.input_tokens,
            "output_tokens":      h.output_tokens,
            "estimated_cost_usd": round(h.estimated_cost_usd, 8),
            "status":             h.status,
        }
        for h in ctx.hop_timings
    ]

    # Compute total per-hop vs pipeline overhead
    hop_total_ms = sum(h.latency_ms for h in ctx.hop_timings)
    overhead_ms  = max(0, ctx.latency_ms - hop_total_ms)

    log_entry = {
        # ── Identity ────────────────────────────────────
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "request_id":         ctx.request_id,
        "user_id":            ctx.user_id,
        "role":               ctx.role,

        # ── Input (privacy-safe) ────────────────────────
        "raw_prompt_hash":    hash_text(ctx.raw_prompt),
        "clean_prompt_hash":  hash_text(ctx.clean_prompt),
        "prompt_length":      len(ctx.raw_prompt),

        # ── Classifier ──────────────────────────────────
        "complexity_tier":    ctx.complexity_tier,
        "intent_class":       ctx.intent_class,

        # ── Scanning findings ───────────────────────────
        "pii_detected":       len(pii_entities) > 0,
        "pii_entities":       pii_entities,
        "injection_detected": len(injection_findings) > 0,
        "injection_findings": injection_findings,
        "output_flagged":     len(secret_findings) > 0,
        "secret_findings":    secret_findings,

        # ── Risk + policy ───────────────────────────────
        "risk_score":         round(ctx.risk_score, 2),
        "policy_decision":    ctx.policy_decision,
        "policy_reason":      ctx.policy_reason,

        # ── Routing ─────────────────────────────────────
        "model_used":         ctx.model_used,

        # ── Per-hop timing breakdown ────────────────────
        "hop_timings":        hops_serialised,
        "hop_total_ms":       hop_total_ms,
        "pipeline_overhead_ms": overhead_ms,
        "total_latency_ms":   ctx.latency_ms,

        # ── Cost attribution ────────────────────────────
        "input_tokens":          ctx.input_tokens,
        "output_tokens":         ctx.output_tokens,
        "estimated_cost_usd":    round(ctx.estimated_cost_usd, 8),
    }

    _audit_logger.info(json.dumps(log_entry))
