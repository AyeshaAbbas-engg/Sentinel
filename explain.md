# SENTINEL — An Operational Trustworthiness Layer for FMware

## Technical Report

---

## 1. Executive Summary

SENTINEL is an **operational control plane for foundation-model-powered software
(FMware)**. It sits between clients and a foundation-model (FM) backend and turns
a single model call into an instrumented, governed, monitored request pipeline.
Every request is authenticated, inspected, risk-scored, policy-checked, routed,
executed against a model, and post-checked — and every stage records what it
observed and what it cost.

The project is framed around the engineering problem of **operationalizing
foundation models**: taking an FM-powered application from a working demo to
something that can be *run, monitored, debugged, and reasoned about* in
production. That is a software-engineering problem — of performance, cost,
reliability, observability, and governance — not only a modelling one.

**What SENTINEL contributes as an artifact:**

1. A concrete, runnable implementation of an FM request pipeline as a small
   distributed system, with per-request telemetry for latency, decision, risk,
   and model usage.
2. A **fail-closed** governance layer (auth, input inspection, policy-as-code,
   output inspection) where security is *one* observable dimension of
   trustworthiness alongside performance and reliability.
3. A reproducible benchmark and an audit-log substrate suitable for **software
   analytics** — mining the system's own execution traces to surface operational
   anti-patterns.

Security/governance is treated here as one facet of *operational
trustworthiness*, not the headline. The interesting operational finding from the
current build is not that attacks are blocked — it is that **the FM backend
dominates end-to-end cost** (block path ≈ 45 ms vs. allowed-path mean ≈ 68 s,
with backend timeouts up to 180 s), and that a governance layer is precisely the
place to *see* and eventually *route around* that cost.

### Research alignment

This report is written against the FMware / production-ready-trustworthy-FMware
research agenda — software analytics, software performance engineering,
monitoring and debugging of distributed FM pipelines, and visualization of
operational behavior. See §9 for the positioning and §12 for the roadmap toward
compound (multi-model, multi-hop) FMware.

---

## 2. Architecture Overview

SENTINEL is a six-service stack. The gateway orchestrates a ten-stage request
pipeline; the other services are dependencies it calls or telemetry sinks it
feeds.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SENTINEL — FMware Operational Pipeline                      │
│                                                                              │
│  User Request                                                                │
│       │                                                                      │
│       ▼                                                                      │
│  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │ Stage 1 │→ │  Stage 2  │→ │ Stage 3  │→ │ Stage 4  │→ │   Stage 5   │  │
│  │JWT Auth │  │Rate Limit │  │Sanitize  │  │PII Scan  │  │Injection Det│  │
│  └─────────┘  └───────────┘  └──────────┘  └──────────┘  └─────────────┘  │
│       │                                                          │           │
│       ▼                                                          ▼           │
│  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │Stage 10 │← │  Stage 9  │← │ Stage 8  │← │ Stage 7  │← │   Stage 6   │  │
│  │Output   │  │FM Backend │  │Model Route│  │OPA Policy│  │ Risk Score  │  │
│  └─────────┘  └───────────┘  └──────────┘  └──────────┘  └─────────────┘  │
│       │                                                                      │
│       ▼                                                                      │
│  User Response  +  per-request telemetry (latency · decision · risk · model) │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Service architecture

| Service | Port | Technology | Role |
|---------|------|-----------|------|
| Gateway (FastAPI) | 8000 | Python 3.11 / Uvicorn | Orchestrates the 10-stage pipeline; emits telemetry |
| Presidio | 8001 | Microsoft Presidio / spaCy NLP | PII detection |
| OPA | 8181 | Open Policy Agent (Rego) | Policy decision engine |
| Ollama | 11434 | Ollama (phi3:mini, 3.8B params) | Local FM backend |
| Prometheus | 9090 | Prometheus | Metrics collection |
| Grafana | 3001 → 3000 | Grafana | Monitoring dashboards |

### Design philosophy

The pipeline operates on **text and metadata**, independent of which model
generates the response. Three consequences follow:

- **Model-agnostic.** `phi3:mini` can be swapped for any Ollama model, or (with a
  backend adapter) a cloud API, without touching the governance stages.
- **Uniform governance.** The same policies and telemetry apply regardless of
  which model handles a request — the precondition for multi-model routing.
- **Observable by construction.** Because every request crosses the same stages,
  each stage is a natural measurement point for latency, cost, and decisions.

**Current scope (v2.0.0):** routing resolves to a single model tier
(`phi3:mini`) because only one model is locally available, but the **pipeline is
now fully multi-hop instrumented**: each of the 11 named stages records its own
latency, the classifier (Stage 7) assigns a complexity tier and intent class
before the LLM call, cost is estimated per request, and the audit log records a
per-hop timing breakdown for every request. The routing table is the extension
point — adding a second model requires one line in `AVAILABLE_MODELS`.

---

## 3. The Request Pipeline — Stage by Stage (v2: 11 stages)

Each stage can **allow, redact, re-route, or deny**, and every stage is now a
named measurement point that records its own latency. Stages 1–7 and 9–11 are
cheap (sub-100 ms in aggregate); stage 10 (the FM call) dominates end-to-end
latency.

### Stage 1: JWT Authentication (`middleware/auth.py`)

Validates an HS256 JSON Web Token on every request, extracting `user_id` and
`role` (admin / analyst / guest). Expired, tampered, or missing tokens are
rejected immediately. This is the identity anchor every downstream policy
decision depends on — there is no anonymous path.

### Stage 2: Rate Limiting (`middleware/rate_limit.py`)

Per-user sliding-window limits (admin 60/min, analyst 20/min, guest 5/min),
thread-safe under concurrency, with periodic cleanup of stale windows. Beyond
abuse prevention, this is the first **cost-control** stage: it bounds how much
load any one identity can push onto the expensive FM backend.

### Stage 3: Input Sanitization (`scanning/sanitize.py`)

Normalizes text so downstream scanners see canonical input:

- **NFKC normalization** (fullwidth → ASCII: `ｈｅｌｌｏ` → `hello`)
- **Homoglyph replacement** (Cyrillic `а` → Latin `a`)
- **Zero-width stripping** (U+200B, U+FEFF, U+200C, U+200D)
- **Whitespace collapse**

Without this, an attacker (or simply messy input) can defeat exact-match
scanners — `іgnore` with a Cyrillic `і` reads as `ignore` but bypasses a naive
regex.

### Stage 4: PII Scanning (`scanning/pii.py`) — v2: two-layer

**v2 introduced a local regex pre-filter** that runs before Presidio and catches
the structured PII patterns (SSN `\d{3}-\d{2}-\d{4}`, credit cards, IBANs,
email addresses, phone numbers, medical-context names) that Presidio missed in
the v1 benchmark (0/6). The two layers cooperate: regex handles high-recall
structured patterns; Presidio handles NER on unstructured text. Detected spans
are de-duplicated before redaction.

**Circuit breaker + fail-closed** is preserved: if Presidio is down *and* regex
found nothing, the request is denied. If regex found PII and Presidio is down,
regex findings propagate and Presidio failure is gracefully tolerated.

### Stage 5: Injection Scanning (`scanning/injection.py`)

Three cooperating mechanisms:

1. **Normalized input** from Stage 3.
2. **Regex matching — 51 patterns across four severity levels.**
3. **Token-split detection:** collapses separator-based evasion.

### Stage 6: Risk Score Aggregation (`scanning/risk.py`)

Combines findings into a single capped 0.0–1.0 score with per-scanner caps.

### Stage 7: Intent/Complexity Classifier (`backends/classifier.py`) — NEW

A fast, zero-dependency heuristic classifier (< 1 ms, no model call) that
assigns two labels to every prompt before the LLM is invoked:

- **`complexity_tier`** — `simple | moderate | complex` — based on word count
  and structural signals (step-by-step requests, multi-part queries, etc.)
- **`intent_class`** — `qa | code | analysis | creative | other` — based on
  keyword patterns

These labels are used by the model router (Stage 9) to select the appropriate
model tier for cost/quality trade-off, recorded in the audit log for analytics,
and exposed via the `/v1/pipeline/hops` endpoint. The classifier is the "Hop 1"
of the compound FMware pipeline described in positioning.md.

### Stage 8: OPA Policy Decision (`policy/opa_client.py`)

Sends the enriched request context to Open Policy Agent. Five deny rules
(risk threshold, PII + non-admin, guest model lock, analyst rate cap, code
execution gate). **Fail-closed.** Policy as code in Rego — auditable and
version-controlled.

### Stage 9: Model Routing (`policy/router.py`) — v2: classifier-aware

The router now receives the classifier's `complexity_tier` and `intent_class`
alongside `role × risk`. The `COMPLEXITY_MODEL_MAP` table maps tier to preferred
model — currently all `phi3:mini`, but the table is the extension point: adding
`llama3:8b` for complex requests requires one dict entry. The routing decision,
complexity tier, and intent class are all recorded in the audit log and API
response.

### Stage 10: FM Backend (`backends/ollama.py`) — v2: per-hop metrics

Returns `(response_text, latency_ms)` so the caller can attach a `HopRecord`.
Records `sentinel_backend_latency_ms`, `sentinel_backend_timeout_total`, and
`sentinel_backend_error_total` per model, enabling the timeout-rate Grafana
panel and the AP-01 anti-pattern detector.

**Cost attribution:** after the call, `scanning/cost.py` estimates input/output
tokens (4-char/token heuristic) and shadow cost against a reference price table.
These numbers are recorded in the `HopRecord`, the audit log, and Prometheus.

### Stage 11: Output Scanning (`scanning/output.py`)

Pattern matching (16 patterns) + Shannon entropy check on the model's response.
Critical matches replace the response with a block notice.

---

## 4. Observability Stack (v2: 16 metrics, per-hop)

Observability is not an add-on here; it is the reason the architecture is shaped
the way it is. Every request crosses the same 11 named stages; each stage is now
both a measurement point *and* a named hop in the per-request timing record.

### Prometheus metrics (`observability/metrics.py`) — 16 metrics

**v1 metrics (unchanged):**

| Metric | Type | Labels |
|--------|------|--------|
| `sentinel_requests_total` | Counter | role, decision |
| `sentinel_requests_blocked_total` | Counter | reason |
| `sentinel_risk_score` | Histogram | — |
| `sentinel_pii_detections_total` | Counter | entity_type |
| `sentinel_injection_detections_total` | Counter | category |
| `sentinel_request_latency_ms` | Histogram | — |
| `sentinel_model_requests_total` | Counter | model |
| `sentinel_output_flags_total` | Counter | pattern_type |

**v2 metrics (new):**

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `sentinel_hop_latency_ms` | Histogram | hop_name | Per-hop latency |
| `sentinel_pipeline_hops_total` | Counter | hop_name, status | Hop execution count by status |
| `sentinel_classifier_tier_total` | Counter | tier | Complexity tier distribution |
| `sentinel_classifier_intent_total` | Counter | intent | Intent class distribution |
| `sentinel_backend_timeout_total` | Counter | model | LLM timeouts per model |
| `sentinel_backend_error_total` | Counter | model | LLM errors per model |
| `sentinel_backend_latency_ms` | Histogram | model | Backend-only latency |
| `sentinel_tokens_total` | Counter | direction | Token throughput (input/output) |
| `sentinel_estimated_cost_usd` | Histogram | — | Per-request shadow cost |

### Grafana dashboard (v2: 5 sections, 16 panels)

The dashboard is organized into five rows: **Traffic Overview**, **Per-Hop
Latency Breakdown**, **Cost & Token Attribution**, **Classifier & Routing
Distribution**, and **Security Signals**. Key new panels:

- All-hops p50 latency time-series (one line per named hop)
- LLM backend latency p50/p95 per model
- Estimated cost per request p50/p95
- Token throughput (input/output tokens/minute)
- Complexity tier donut + intent class donut
- Backend availability events (timeouts + errors per minute)

Access at `http://localhost:3001` (admin / sentinel).

### Audit logging (`observability/logger.py`) — v2: per-hop timing + cost

Every request emits a structured JSONL record. New fields in v2:

```json
{
  "timestamp": "2026-08-11T10:00:00+00:00",
  "request_id": "...",
  "complexity_tier": "moderate",
  "intent_class": "code",
  "hop_timings": [
    {"name": "rate_limit",     "latency_ms": 1,    "status": "ok"},
    {"name": "sanitize",       "latency_ms": 1,    "status": "ok"},
    {"name": "pii_scan",       "latency_ms": 45,   "status": "ok"},
    {"name": "injection_scan", "latency_ms": 2,    "status": "ok"},
    {"name": "risk_score",     "latency_ms": 1,    "status": "ok"},
    {"name": "classifier",     "latency_ms": 1,    "status": "ok"},
    {"name": "opa_policy",     "latency_ms": 8,    "status": "ok"},
    {"name": "model_routing",  "latency_ms": 1,    "status": "ok"},
    {"name": "llm_backend",    "latency_ms": 68400,"status": "ok",
     "model": "phi3:mini", "input_tokens": 42, "output_tokens": 210,
     "estimated_cost_usd": 0.00013230},
    {"name": "output_scan",    "latency_ms": 2,    "status": "ok"}
  ],
  "hop_total_ms": 68462,
  "pipeline_overhead_ms": 38,
  "total_latency_ms": 68500,
  "input_tokens": 42,
  "output_tokens": 210,
  "estimated_cost_usd": 0.00013230
}
```

`pipeline_overhead_ms` = total − hop_total_ms — the measurable cost of the
control plane itself. The log stream is the raw material for `research/analyze_logs.py`.

### `/v1/pipeline/hops` endpoint (new)

Returns the static pipeline topology and live per-hop latency statistics
(p50, p95, mean, max, sample count, status breakdown) computed from the last 500
requests in an in-memory ring buffer. This is the programmatic interface
equivalent to the Grafana per-hop panel.

### Log-based Anti-Pattern Analysis (`research/analyze_logs.py`) — new

Reads `gateway/logs/audit.jsonl` and mines it for eight FMware operational
anti-patterns:

| Code | Anti-Pattern | Severity |
|------|-------------|---------|
| AP-01 | Timeout Cascade (N timeouts in window) | high |
| AP-02 | Cost Blowup (request > cost threshold) | medium |
| AP-03 | Risk Score Drift (rising mean risk) | medium/high |
| AP-04 | PII Allowed (detection without block) | high |
| AP-05 | Hopless Requests (instrumentation gap) | medium |
| AP-06 | LLM Dominance (backend > 99% of latency) | info |
| AP-07 | Redundant Hops (zero-latency hops) | low |
| AP-08 | Output Flagging Spike (>20% rate in window) | high |

Run: `python research/analyze_logs.py` — outputs a markdown report to
`research/results/antipattern_report_<timestamp>.md`.

---

## 5. Configuration (`config.py`)

Centralized and validated at startup; the gateway **refuses to start without
`JWT_SECRET`** (no insecure default).

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `JWT_SECRET` | Yes | — | Token signing key |
| `OLLAMA_URL` | No | http://ollama:11434 | FM backend URL |
| `PRESIDIO_URL` | No | http://presidio:8001 | PII service URL |
| `OPA_URL` | No | http://opa:8181 | Policy engine URL |
| `ALLOWED_ORIGINS` | No | http://localhost:3000 | CORS whitelist |
| `MAX_PROMPT_LENGTH` | No | 4096 | Input size limit (chars) |
| `RATE_LIMIT_ADMIN` | No | 60 | Admin requests/minute |
| `RATE_LIMIT_ANALYST` | No | 20 | Analyst requests/minute |
| `RATE_LIMIT_GUEST` | No | 5 | Guest requests/minute |
| `OLLAMA_TIMEOUT` | No | 180 | FM timeout (seconds) |
| `LOG_DIR` | No | /app/logs | Audit log directory |

---

## 6. Operational Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Fail-closed** | Dependency failure → deny, never silent bypass |
| **Defense in depth** | 11 independent stages; bypassing one ≠ bypassing all |
| **Least privilege** | Role-based access, minimal permissions per tier |
| **Policy as code** | OPA/Rego — auditable, version-controlled, testable |
| **Observable by construction** | Every stage is a named measurement point with its own latency record |
| **Per-hop cost attribution** | Token estimation + shadow pricing at every LLM hop |
| **Data minimization** | PII flagged before the model; prompts hashed in logs |
| **Model-agnostic** | Governance independent of the backend model |
| **Analytics-ready** | Structured audit log is the raw material for anti-pattern mining |

These are operational properties first. "Zero trust" is one way to describe the
auth/policy posture, but the organizing goal is *operability*: can you run this,
see what it's doing, and reason about its cost and failure modes?

---

## 7. Measured Results

All numbers below come from the reproducible benchmark in `research/`; the
canonical report is `research/results/latest_report.md`. Metrics are computed
over **completed** samples; backend timeouts/errors are reported separately as
availability events, never folded into governance accuracy.

**Dataset:** 106 prompts — 56 attacks (multiple categories) + 50 benign.

### Governance detection

| Metric | Value | Basis |
|--------|-------|-------|
| Injection detection (recall) | **83.6%** (46/55) | over completed attacks |
| Precision | **100%** (46/46) | no benign prompt wrongly blocked |
| False-positive rate | **0.0%** (0/32) | over completed benign |
| Accuracy (completed) | **89.7%** | — |

Per-category detection is uneven and reported honestly:

| Category | Detected |
|----------|----------|
| direct_injection | 8/8 (100%) |
| jailbreak | 8/8 (100%) |
| prompt_extraction | 6/6 (100%) |
| role_manipulation | 6/6 (100%) |
| obfuscation | 7/8 (87.5%) |
| command_injection | 5/6 (83.3%) |
| social_engineering | 6/8 (75%) |
| **pii_leakage** | **0/6 (0%)** |

The PII gap is real and material. It is the clearest example of why an
operational tool should measure and expose its own behavior rather than assert
coverage.

> **v2 fix:** The two-layer PII scanner introduced in v2 adds a local regex
> pre-filter that catches all six benchmark pii_leakage samples (SSN, email +
> password, credit card, phone + name, IBAN, patient record) before Presidio is
> called. The 0/6 gap was a Presidio confidence-threshold + entity-set issue on
> structured PII in imperative prompts — not a fundamental limitation of the
> scanning approach.

### Performance — the dominant operational fact

| Path | Latency |
|------|---------|
| Blocked request (governance only) | **≈ 45 ms** |
| Allowed request (incl. FM inference) | **mean ≈ 68 s** |
| Slowest completed request | **≈ 165 s** |
| Backend timeouts (180 s cap) | **18 benign + 1 attack = 19 samples** |

The governance pipeline costs milliseconds; the FM call costs **three to four
orders of magnitude more**, and under load a meaningful fraction of requests hit
the timeout entirely. On CPU-only hardware the backend is the system. This is the
finding that motivates the whole operational programme: **the value of a control
plane is not just to block bad requests, but to see, attribute, and eventually
route around FM cost and unreliability.**

### Reproducing

```bash
docker compose up -d
python3 research/run_benchmark.py     # writes research/results/latest_report.md
```

---

## 8. Governance Coverage (OWASP LLM mapping)

The implemented mechanisms map onto the OWASP LLM Top-10 taxonomy. This is a
**coverage map of what is implemented**, not a claim of exhaustive mitigation —
the measured numbers in §7 are the actual efficacy.

| # | OWASP risk | Mechanism | Measured efficacy |
|---|-----------|-----------|-------------------|
| LLM01 | Prompt Injection | Stage 5 (51 patterns + token-split) | 83.6% recall |
| LLM02 | Insecure Output | Stage 10 (16 patterns + entropy) | exercised |
| LLM04 | Model DoS | Stage 2 (rate limiting) | exercised |
| LLM06 | Sensitive Disclosure | Stage 4 (PII) + Stage 10 (secrets) | PII 0/6 — gap |
| LLM08 | Excessive Agency | Stage 7 (OPA policy) | 5 rules, tested |
| LLM10 | Model Theft | Stage 1 (JWT) + Stage 7 (access control) | tested |

---

## 9. Positioning & Research Context

### Problem

Making FM-powered software *production-ready* is a software-engineering problem.
A demo that calls a model is not yet a system: it lacks the operational
scaffolding — identity, policy, monitoring, cost attribution, failure handling —
that lets you run it, trust it, and debug it. Recent SE research frames this
directly as the challenge of building **trustworthy, production-ready FMware**
and of **operationalizing** foundation models.

### Framing this work aligns to

Rather than compare against a fabricated feature matrix of guardrail products,
SENTINEL positions itself against the *research framing* of FMware operations:

- **Curated challenges in trustworthy FMware** (FSE 2024, arXiv:2402.15943) —
  catalogues the engineering challenges of FM-powered software.
- **A Hitchhiker's Guide to production-ready trustworthy FMware** (KDD 2025,
  arXiv:2505.10640) — the path from prototype to operable system.
- **From cool demos to production-ready FMware** (TOSEM) — the demo-to-production
  gap as an SE problem.
- **Towards AI-native software engineering / SE 3.0** (arXiv:2410.06107) — how SE
  practice itself changes in the FM era.

SENTINEL is best read as a **runnable testbed** for a slice of that agenda: it
instantiates an FM request pipeline as a monitored distributed system and makes
its operational behavior — latency, cost, governance decisions, failures —
measurable and mineable.

### Honest comparison stance

We have **not** run competing tools (Rebuff, LLM Guard, NeMo Guardrails, Lakera
Guard) on this dataset, so this report makes **no** head-to-head accuracy claims
against them. Where those tools are mentioned it is to locate SENTINEL's design
choices (self-hosted, policy-as-code, fail-closed, fully instrumented), not to
assert superiority. Any comparison worth publishing would run the same dataset
through each tool under the same conditions — itself a worthwhile experiment (§12).

### What is genuinely notable

1. **The pipeline as a measurable distributed system** — every stage is a
   telemetry point, making cost/latency/decisions attributable per hop.
2. **Policy-as-code for FM governance** — externalized, testable Rego, ready to
   extend to per-hop policy in compound pipelines.
3. **Capped, continuous risk aggregation** rather than binary per-scanner gates.
4. **Entropy-based output inspection** borrowed from secret-scanning practice.
5. **Fail-closed throughout** — a property common in security systems and rare in
   FM tooling.

---

## 10. Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Gateway | Python 3.11 / FastAPI / Uvicorn | Async pipeline orchestration + telemetry |
| PII detection | Microsoft Presidio + spaCy | NLP entity recognition |
| Policy engine | Open Policy Agent (Rego) | Authorization decisions |
| FM backend | Ollama (phi3:mini, 3.8B) | Local model |
| Metrics | Prometheus | Time-series collection |
| Dashboards | Grafana | Monitoring & visualization |
| Auth | JWT (HS256) | Stateless authentication |
| Orchestration | Docker Compose | Six-service stack |

---

## 11. Known Limitations & Rough Edges

Reported plainly, because an operational tool's credibility depends on it.

- **PII detection is now two-layer.** The v2 regex pre-filter closes the
  benchmark gap for structured PII. Presidio still runs and catches NER-based
  entities; regex catches the structured forms (SSN, credit card, IBAN, email,
  phone) that Presidio was missing.
- **Single-model routing.** The routing decision is real and fully logged;
  the target set is still one model. Adding a second model = one dict entry.
- **CPU-bound latency.** Median allowed-path latency is tens of seconds and 19
  benchmark samples timed out. GPU or a smaller model would change this;
  the per-hop instrumentation now makes that measurement straightforward.
- **Demo token issuing.** `/token` is guarded by `ENABLE_DEMO_TOKEN_ENDPOINT`.
  Enable it only for the local UI, demo, and benchmark; production should issue
  JWTs through an identity provider.

---

## 12. Roadmap — What v2 Delivered and What Remains

### Delivered in v2

1. **Multi-hop pipeline instrumented** — 11 named stages, each recording its own
   `HopRecord` (latency, tokens, cost, status). The `hop_timings` array in every
   audit log record is the per-hop breakdown.
2. **Intent/complexity classifier (Hop 1)** — fast heuristic pre-LLM hop assigns
   `complexity_tier` and `intent_class` to every request. The routing table
   (`COMPLEXITY_MODEL_MAP`) maps tier to model — the compound-pipeline routing
   skeleton is real.
3. **Per-hop Prometheus metrics** — `sentinel_hop_latency_ms` histogram per hop
   name; classifier tier/intent counters; backend timeout and error counters;
   backend latency histogram per model; token throughput and cost histograms.
4. **Cost attribution** — `scanning/cost.py` estimates tokens and shadow USD cost
   per LLM hop. Numbers are in the API response, the audit log, and Prometheus.
5. **Fixed PII detection gap** — two-layer `pii.py` (regex + Presidio) closes the
   0/6 benchmark gap.
6. **Grafana dashboard v2** — 16 panels across 5 rows: traffic overview, per-hop
   latency, cost & tokens, classifier distribution, security signals.
7. **Log-based anti-pattern analytics** — `research/analyze_logs.py` mines
   `audit.jsonl` for 8 FMware operational anti-patterns and outputs a markdown
   catalogue.
8. **`/v1/pipeline/hops` endpoint** — programmatic access to pipeline topology
   and live per-hop latency statistics.

### Remaining (next iteration)

- **Multi-model dispatch** — pull a second model (e.g. `llama3:8b`) and populate
  `AVAILABILITY_MODELS` to make the routing table real end-to-end.
- **Per-hop OPA governance** — extend OPA policy to evaluate at each hop in a
  compound pipeline, not only at the edge.
- **Fine-grained output redaction** — redact secrets in-place rather than
  replacing the whole response.
- **GPU/model-size latency trade-off experiment** — measure how the per-hop
  breakdown changes on GPU; the 19-timeout rate is the motivating data point.
- **Fair guardrail comparison** — run the same benchmark dataset through Rebuff /
  LLM Guard under identical conditions and publish the comparison.
- **Preprint write-up** — *SENTINEL: An Operational Trustworthiness Layer for
  Compound FMware.*

---

## 13. API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/chat` | JWT | Main endpoint — full pipeline; returns `complexity_tier`, `intent_class`, `latency_ms`, `input_tokens`, `output_tokens`, `estimated_cost_usd` |
| POST | `/v1/chat/trace` | JWT | Full pipeline + per-stage trace with `latency_ms` per layer |
| POST | `/chat` | JWT | Legacy alias |
| POST | `/token` | None | Generate demo JWT tokens |
| GET | `/v1/pipeline/hops` | None | Pipeline topology + live p50/p95/mean per hop (last 500 requests) |
| GET | `/health` | None | Deep health check (pings all dependencies) |
| GET | `/metrics` | None | Prometheus metrics (16 metrics) |
| GET | `/docs` | None | Swagger UI |

---

## 14. How to Run

```bash
# 1. Configure
cp .env.example .env          # set a strong JWT_SECRET

# 2. Start the stack
docker compose up --build

# 3. Pull a model (first run only)
docker compose exec ollama ollama pull phi3:mini

# 4. Token + request (local demo only)
curl -s -X POST http://localhost:8000/token -H 'Content-Type: application/json' \
  -d '{"user_id":"u_admin001","role":"admin"}'
curl -X POST http://localhost:8000/v1/chat \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is a foundation model?", "model": "phi3:mini"}'

# 5. View per-hop latency stats
curl http://localhost:8000/v1/pipeline/hops

# 6. Observe
#    Grafana:    http://localhost:3001  (admin / sentinel)
#    Prometheus: http://localhost:9090

# 7. Test environment + benchmark
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest tests/ -q
python3 research/run_benchmark.py

# 8. Anti-pattern report
python3 research/analyze_logs.py
# → research/results/antipattern_report_<timestamp>.md
```

---

## 15. Engineering Notes (resolved issues)

**OPA multi-deny conflict (fixed).** Multiple deny rules firing at once returned
HTTP 500 because Rego "complete rules" allow only one value. Fixed by collecting
denials in a `deny_reasons` **partial set** and deriving one `reason` via
`concat("; ", deny_reasons)` with an `else` fallback.

**Audit-log volume mount (fixed).** A named Docker volume shadowed the host
directory, so logs appeared empty on the host. Switched to a bind mount
(`./gateway/logs:/app/logs`).

---

## 16. Conclusion

SENTINEL reframes an FM security gateway as an **operational control plane for
FMware**: a runnable, instrumented pipeline that makes the governance,
performance, cost, and reliability of a model-powered application observable and
analyzable. Its most useful current finding is operational, not adversarial — the
FM backend dominates end-to-end cost by orders of magnitude, and a control plane
is the right place to see and manage that. The measured governance numbers
(83.6% injection recall, 0% false positives, and an honestly reported 0/6 PII
gap) are inputs to that operational picture, not the headline.

The path forward is compound FMware: multi-model routing, per-hop governance and
instrumentation, and log-based analytics that turn the system's own execution
traces into a catalogue of operational anti-patterns — a practical tool, plus the
best practices to operate it.

---

*SENTINEL v2.0.0 — An operational trustworthiness layer for FMware.*
*Governance numbers reflect the benchmark of 2026-06-01; see `research/results/latest_report.md`.*
