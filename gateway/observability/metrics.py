# ════════════════════════════════════════════════════════
# SENTINEL — Prometheus Metrics
# 8 metrics exposed at GET /metrics
# Scraped by Prometheus every 15 seconds
# ════════════════════════════════════════════════════════

from prometheus_client import Counter, Histogram, REGISTRY
from prometheus_client.exposition import generate_latest
from prometheus_client import CONTENT_TYPE_LATEST

# ── Counter: total requests by role and decision ─────────
requests_total = Counter(
    "sentinel_requests_total",
    "Total requests processed by the gateway",
    ["role", "decision"]
)

# ── Counter: blocked requests by reason ─────────────────
requests_blocked_total = Counter(
    "sentinel_requests_blocked_total",
    "Total requests blocked, labeled by reason",
    ["reason"]
)

# ── Histogram: risk score distribution ───────────────────
risk_score_histogram = Histogram(
    "sentinel_risk_score",
    "Distribution of risk scores across all requests",
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)

# ── Counter: PII detections by entity type ───────────────
pii_detections_total = Counter(
    "sentinel_pii_detections_total",
    "PII detections labeled by entity type",
    ["entity_type"]
)

# ── Counter: injection detections by category ────────────
injection_detections_total = Counter(
    "sentinel_injection_detections_total",
    "Injection detections labeled by category",
    ["category"]
)

# ── Histogram: end-to-end request latency ────────────────
request_latency_ms = Histogram(
    "sentinel_request_latency_ms",
    "End-to-end request latency in milliseconds",
    buckets=[50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000]
)

# ── Counter: requests per model backend ──────────────────
model_requests_total = Counter(
    "sentinel_model_requests_total",
    "Requests per model backend",
    ["model"]
)

# ── Counter: output scanner flags by pattern type ────────
output_flags_total = Counter(
    "sentinel_output_flags_total",
    "Output scanner flags labeled by pattern type",
    ["pattern_type"]
)


# ── Helper functions called from main.py ─────────────────

def record_request(role: str, decision: str, risk_score: float, latency_ms: int):
    """Record a completed request with its outcome."""
    requests_total.labels(role=role, decision=decision).inc()
    risk_score_histogram.observe(risk_score)
    request_latency_ms.observe(latency_ms)


def record_block(reason: str):
    """Record a blocked request with the reason code."""
    # Normalise reason to a short label
    if "risk score" in reason.lower():
        label = "risk_threshold"
    elif "pii" in reason.lower():
        label = "pii_detected"
    elif "code execution" in reason.lower():
        label = "code_execution"
    elif "rate limit" in reason.lower():
        label = "rate_limit"
    elif "guest" in reason.lower():
        label = "role_violation"
    elif "opa" in reason.lower():
        label = "opa_error"
    else:
        label = "policy_block"
    requests_blocked_total.labels(reason=label).inc()


def record_pii(entities: list):
    """Record each detected PII entity type."""
    for entity in entities:
        pii_detections_total.labels(entity_type=entity).inc()


def record_injection(findings: list):
    """Record each injection finding category."""
    for f in findings:
        injection_detections_total.labels(category=f.scanner).inc()


def record_model(model: str):
    """Record which model handled the request."""
    model_requests_total.labels(model=model).inc()


def record_output_flag(pattern_type: str):
    """Record an output scanner flag."""
    output_flags_total.labels(pattern_type=pattern_type).inc()