# ════════════════════════════════════════════════════════
# SENTINEL — Prometheus Metrics  (v2: per-hop + cost)
#
# 16 metrics exposed at GET /metrics
# Scraped by Prometheus every 15 s
#
# New in v2:
#   - sentinel_hop_latency_ms      histogram (per named hop)
#   - sentinel_classifier_tier_total counter  (complexity tier)
#   - sentinel_classifier_intent_total counter (intent class)
#   - sentinel_backend_timeout_total counter   (per model)
#   - sentinel_backend_latency_ms   histogram  (per model)
#   - sentinel_tokens_total         counter    (input/output)
#   - sentinel_estimated_cost_usd   histogram
#   - sentinel_pipeline_hops_total  counter    (hop name × status)
# ════════════════════════════════════════════════════════

from prometheus_client import Counter, Histogram

# ── v1 metrics (unchanged) ───────────────────────────────

requests_total = Counter(
    "sentinel_requests_total",
    "Total requests processed by the gateway",
    ["role", "decision"]
)

requests_blocked_total = Counter(
    "sentinel_requests_blocked_total",
    "Total requests blocked, labeled by reason",
    ["reason"]
)

risk_score_histogram = Histogram(
    "sentinel_risk_score",
    "Distribution of risk scores across all requests",
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)

pii_detections_total = Counter(
    "sentinel_pii_detections_total",
    "PII detections labeled by entity type",
    ["entity_type"]
)

injection_detections_total = Counter(
    "sentinel_injection_detections_total",
    "Injection detections labeled by category",
    ["category"]
)

request_latency_ms = Histogram(
    "sentinel_request_latency_ms",
    "End-to-end request latency in milliseconds",
    buckets=[50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 180000]
)

model_requests_total = Counter(
    "sentinel_model_requests_total",
    "Requests per model backend",
    ["model"]
)

output_flags_total = Counter(
    "sentinel_output_flags_total",
    "Output scanner flags labeled by pattern type",
    ["pattern_type"]
)

# ── v2 metrics ───────────────────────────────────────────

# Per-hop latency histogram — labeled by hop_name
# Allows Grafana to render a per-hop latency breakdown panel
hop_latency_ms = Histogram(
    "sentinel_hop_latency_ms",
    "Per-named-hop latency in milliseconds",
    ["hop_name"],
    buckets=[1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000,
             10000, 30000, 60000, 120000, 180000]
)

# Pipeline hop status counter (hop_name × status: ok|blocked|error|skipped)
pipeline_hops_total = Counter(
    "sentinel_pipeline_hops_total",
    "Pipeline hop executions labeled by name and status",
    ["hop_name", "status"]
)

# Classifier output counters
classifier_tier_total = Counter(
    "sentinel_classifier_tier_total",
    "Requests per complexity tier assigned by the classifier",
    ["tier"]   # simple | moderate | complex | unknown
)

classifier_intent_total = Counter(
    "sentinel_classifier_intent_total",
    "Requests per intent class assigned by the classifier",
    ["intent"]  # qa | code | analysis | creative | other | unknown
)

# Backend availability
backend_timeout_total = Counter(
    "sentinel_backend_timeout_total",
    "LLM backend timeouts per model",
    ["model"]
)

backend_error_total = Counter(
    "sentinel_backend_error_total",
    "LLM backend errors (non-timeout) per model",
    ["model"]
)

backend_latency_ms = Histogram(
    "sentinel_backend_latency_ms",
    "LLM backend response latency in milliseconds, per model",
    ["model"],
    buckets=[500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 180000]
)

# Token and cost attribution
tokens_total = Counter(
    "sentinel_tokens_total",
    "Estimated token usage labeled by direction (input|output)",
    ["direction"]
)

estimated_cost_usd = Histogram(
    "sentinel_estimated_cost_usd",
    "Estimated per-request cost in USD",
    buckets=[0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0]
)


# ── Helper functions ─────────────────────────────────────

def record_request(role: str, decision: str, risk_score: float, latency_ms: int):
    """Record a completed request."""
    requests_total.labels(role=role, decision=decision).inc()
    risk_score_histogram.observe(risk_score)
    request_latency_ms.observe(latency_ms)


def record_block(reason: str):
    """Record a blocked request with a normalised reason label."""
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
    for entity in entities:
        pii_detections_total.labels(entity_type=entity).inc()


def record_injection(findings: list):
    for f in findings:
        injection_detections_total.labels(category=f.scanner).inc()


def record_model(model: str):
    model_requests_total.labels(model=model).inc()


def record_output_flag(pattern_type: str):
    output_flags_total.labels(pattern_type=pattern_type).inc()


# ── v2 helpers ───────────────────────────────────────────

def record_hop(name: str, latency_ms_val: int, status: str = "ok"):
    """Record a single named pipeline hop."""
    hop_latency_ms.labels(hop_name=name).observe(latency_ms_val)
    pipeline_hops_total.labels(hop_name=name, status=status).inc()


def record_classifier(tier: str, intent: str):
    """Record classifier output."""
    classifier_tier_total.labels(tier=tier).inc()
    classifier_intent_total.labels(intent=intent).inc()


def record_backend_timeout(model: str):
    backend_timeout_total.labels(model=model).inc()


def record_backend_error(model: str):
    backend_error_total.labels(model=model).inc()


def record_backend_latency(model: str, latency_ms_val: int):
    backend_latency_ms.labels(model=model).observe(latency_ms_val)


def record_tokens_and_cost(input_tok: int, output_tok: int, cost_usd: float):
    """Record token usage and estimated cost."""
    tokens_total.labels(direction="input").inc(input_tok)
    tokens_total.labels(direction="output").inc(output_tok)
    estimated_cost_usd.observe(cost_usd)
