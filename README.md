# SENTINEL

**An operational trustworthiness layer for FMware (foundation-model-powered software).**

SENTINEL sits between clients and a foundation-model backend and treats every
request as a traversal through an instrumented, governed, monitored pipeline.
Every stage records its own latency, the classifier assigns intent and complexity
before the LLM is invoked, cost is attributed per hop, and the audit log is a
mineable substrate for operational anti-pattern analysis.

The project is framed around the engineering problem of **operationalizing
foundation models** — moving from a working demo to something that can be run,
monitored, debugged, and reasoned about in production. Security/governance is
*one* of the dimensions SENTINEL makes observable; performance, cost, and
reliability are first-class alongside it.

> **Research alignment.** This repository is developed toward the FMware /
> "production-ready trustworthy FMware" research agenda — operational tooling,
> software performance engineering, monitoring of distributed FM pipelines, and
> log-based software analytics. See [`docs/positioning.md`](docs/positioning.md)
> for the research framing and preprint roadmap.

---

## The request pipeline (v2: 11 stages, all instrumented)

```
User Request
     │
     ▼
┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
│ Stage 1 │→ │  Stage 2  │→ │ Stage 3  │→ │ Stage 4  │→ │   Stage 5   │
│JWT Auth │  │Rate Limit │  │Sanitize  │  │PII Scan  │  │Injection Det│
└─────────┘  └───────────┘  └──────────┘  └──────────┘  └─────────────┘
                                                               │
                                                               ▼
┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
│Stage 6  │→ │  Stage 7  │→ │ Stage 8  │→ │ Stage 9  │  │   Stage 6   │
│Risk     │  │Classifier │  │OPA Policy│  │Model Rte │  │ Risk Score  │
│Score    │  │(Hop 1)    │  │          │  │          │  │             │
└─────────┘  └───────────┘  └──────────┘  └──────────┘  └─────────────┘
                                                               │
                                                               ▼
                                          ┌──────────┐  ┌─────────────┐
                                          │Stage 11  │← │  Stage 10   │
                                          │Output Scn│  │ FM Backend  │
                                          └──────────┘  └─────────────┘
     │
     ▼
User Response  +  complexity_tier, intent_class, latency_ms, input_tokens,
                  output_tokens, estimated_cost_usd, per-hop timing breakdown
```

Every stage is a checkpoint (allow / redact / re-route / deny) that records its
own `latency_ms`. The pipeline is **fail-closed**: dependency failure → deny,
never silent pass-through.

---

## What it does (v2.0.0)

### Governance
- **Two-layer PII scanning** — local regex pre-filter (SSN, credit card, IBAN,
  email, phone, medical context) + Microsoft Presidio NER, circuit-breaker,
  fail-closed. Closes the v1 0/6 pii_leakage benchmark gap.
- **Prompt-injection detection** — 51 regex patterns + token-split heuristic.
- **Policy-as-code** — Open Policy Agent (Rego) with 5 deny rules; fail-closed.
- **Output scanning** — 16 secret/credential patterns + Shannon entropy.
- **Capped risk scoring** — continuous 0.0–1.0 with per-scanner caps.

### Operations & observability
- **Intent/Complexity Classifier (Hop 1)** — heuristic pre-LLM stage (< 1 ms)
  assigns `complexity_tier` (simple/moderate/complex) and `intent_class`
  (qa/code/analysis/creative/other) to every request. Powers routing and analytics.
- **Per-hop timing** — every stage records its own `latency_ms` in a `HopRecord`.
  The audit log includes the full `hop_timings` array + `pipeline_overhead_ms`.
- **Cost attribution** — token estimation + shadow USD pricing per LLM hop.
- **16 Prometheus metrics** (8 original + 8 new in v2).
- **Grafana dashboard v2** — 16 panels across 5 rows including per-hop latency
  breakdown, cost/token throughput, classifier tier distribution, and backend
  availability events.
- **`/v1/pipeline/hops` endpoint** — live p50/p95/mean per hop from last 500 requests.
- **Log-based anti-pattern analysis** — `research/analyze_logs.py` mines
  `audit.jsonl` for 8 FMware operational anti-patterns.

### Measured operational reality (benchmark run 2026-06-01)

| Signal | Value | Note |
|--------|-------|------|
| Injection detection (recall) | 83.6% (46/55) | over completed attack samples |
| False-positive rate | 0.0% (0/32) | no benign prompt wrongly blocked |
| PII-category detection (v1) | 0/6 | gap addressed in v2 two-layer scanner |
| Mean blocked-path latency | ~45 ms | governance only |
| Mean allowed-path latency | ~68 s | model inference dominates |
| Backend timeouts | 19 samples | excluded from classifier metrics |

The latency asymmetry is the key finding: the FM backend dominates end-to-end
cost by 3–4 orders of magnitude. The control plane's value is to *see, attribute,
and route around* that cost — not only to block bad requests.

---

## Architecture

| Service | Port | Technology | Role |
|---------|------|------------|------|
| Gateway | 8000 | FastAPI 0.111 / Uvicorn | 11-stage pipeline + telemetry |
| Presidio | 8001 | Microsoft Presidio / spaCy | PII NER (layer B) |
| OPA | 8181 | Open Policy Agent | Policy decisions (Rego) |
| Ollama | 11434 | Ollama | Local FM backend (`phi3:mini`) |
| Prometheus | 9090 | Prometheus | Metrics collection |
| Grafana | 3001 → 3000 | Grafana | Monitoring dashboards (v2: 16 panels) |

---

## Quick start

```bash
# 1. Configure
cp .env.example .env       # set JWT_SECRET (required — gateway won't start without it)

# 2. Start
docker compose up --build

# 3. Pull model (first run)
docker compose exec ollama ollama pull phi3:mini

# 4. Get a token
python gateway/generate_token.py

# 5. Chat
curl -X POST http://localhost:8000/v1/chat \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is a foundation model?", "model": "phi3:mini"}'

# 6. Per-stage trace
curl -X POST http://localhost:8000/v1/chat/trace \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is a foundation model?", "model": "phi3:mini"}'

# 7. Live per-hop stats
curl http://localhost:8000/v1/pipeline/hops

# 8. Benchmark
python3 research/run_benchmark.py

# 9. Anti-pattern report
python3 research/analyze_logs.py
```

---

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/chat` | JWT | Full pipeline; returns `complexity_tier`, `intent_class`, `latency_ms`, `input_tokens`, `output_tokens`, `estimated_cost_usd` |
| POST | `/v1/chat/trace` | JWT | Same pipeline + per-stage trace with `latency_ms` per layer |
| POST | `/chat` | JWT | Legacy alias |
| POST | `/token` | None | Generate demo JWT tokens |
| GET | `/v1/pipeline/hops` | None | Pipeline topology + live p50/p95/mean per hop (last 500 req) |
| GET | `/health` | None | Deep health check (pings all services) |
| GET | `/metrics` | None | Prometheus metrics (16 metrics) |
| GET | `/docs` | None | Swagger UI |

### Response fields (v2, allowed)

```json
{
  "request_id": "...",
  "response": "...",
  "model_used": "phi3:mini",
  "routing_tier": "admin_low_risk",
  "routing_reason": "Admin role, low risk (0.00) | simple complexity → phi3:mini",
  "complexity_tier": "simple",
  "intent_class": "qa",
  "risk_score": 0.0,
  "risk_level": "low",
  "policy_decision": "allow",
  "pii_detected": false,
  "injection_detected": false,
  "output_flagged": false,
  "latency_ms": 68450,
  "input_tokens": 9,
  "output_tokens": 210,
  "estimated_cost_usd": 0.00012735
}
```

---

## Pipeline stages

| Stage | Component | Function |
|-------|-----------|----------|
| 1 | JWT Auth | HS256 token verification; extracts user_id and role |
| 2 | Rate Limit | Sliding window: admin 60/min, analyst 20/min, guest 5/min |
| 3 | Sanitize | NFKC, homoglyph replacement, zero-width stripping |
| 4 | PII Scan | **v2:** regex pre-filter (SSN/CC/IBAN/email/phone) + Presidio NER |
| 5 | Injection | 51 patterns + token-split heuristic |
| 6 | Risk Score | Capped aggregation → 0.0–1.0 |
| 7 | Classifier | **NEW:** < 1 ms heuristic → complexity_tier + intent_class |
| 8 | OPA Policy | Rego: risk threshold, PII, guest lock, rate cap, code gate |
| 9 | Model Route | **v2:** classifier-aware; COMPLEXITY_MODEL_MAP → model selection |
| 10 | FM Backend | **v2:** returns (text, latency_ms); records timeout/error metrics |
| 11 | Output Scan | 16 secret patterns + Shannon entropy |

---

## Monitoring

- **Grafana**: http://localhost:3001 (admin / sentinel)
- **Prometheus**: http://localhost:9090

### Prometheus metrics (v2: 16 total)

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
| `sentinel_hop_latency_ms` | Histogram | **hop_name** |
| `sentinel_pipeline_hops_total` | Counter | hop_name, status |
| `sentinel_classifier_tier_total` | Counter | **tier** |
| `sentinel_classifier_intent_total` | Counter | **intent** |
| `sentinel_backend_timeout_total` | Counter | **model** |
| `sentinel_backend_error_total` | Counter | model |
| `sentinel_backend_latency_ms` | Histogram | model |
| `sentinel_tokens_total` | Counter | direction |
| `sentinel_estimated_cost_usd` | Histogram | — |

### Audit log fields (v2)

Every JSONL record now includes:

```
complexity_tier, intent_class,
hop_timings: [{name, latency_ms, model?, input_tokens, output_tokens,
               estimated_cost_usd, status}],
hop_total_ms, pipeline_overhead_ms, total_latency_ms,
input_tokens, output_tokens, estimated_cost_usd
```

---

## Log-based anti-pattern analysis

```bash
python research/analyze_logs.py [--log-file PATH] [--window 300]
# → research/results/antipattern_report_<timestamp>.md
```

Detects 8 FMware operational anti-patterns from `audit.jsonl`:

| Code | Pattern | Severity |
|------|---------|----------|
| AP-01 | Timeout Cascade | high |
| AP-02 | Cost Blowup | medium |
| AP-03 | Risk Score Drift | medium/high |
| AP-04 | PII Allowed (detection without block) | high |
| AP-05 | Hopless Requests (instrumentation gap) | medium |
| AP-06 | LLM Dominance (backend > 99% of latency) | info |
| AP-07 | Redundant Hops | low |
| AP-08 | Output Flagging Spike | high |

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | **Yes** | — | Token signing key |
| `OLLAMA_URL` | No | `http://ollama:11434` | FM backend |
| `PRESIDIO_URL` | No | `http://presidio:8001` | PII service |
| `OPA_URL` | No | `http://opa:8181` | Policy engine |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` | CORS whitelist |
| `MAX_PROMPT_LENGTH` | No | `4096` | Max input characters |
| `RATE_LIMIT_ADMIN` | No | `60` | Admin requests/min |
| `RATE_LIMIT_ANALYST` | No | `20` | Analyst requests/min |
| `RATE_LIMIT_GUEST` | No | `5` | Guest requests/min |
| `OLLAMA_TIMEOUT` | No | `180` | FM timeout (seconds) |
| `LOG_DIR` | No | `/app/logs` | Audit log directory |

---

## Policy rules (`opa/policies/sentinel.rego`)

| Rule | Condition | Action |
|------|-----------|--------|
| Risk hard block | risk_score > 0.7 | Deny all roles |
| PII restriction | PII detected + role ≠ admin | Deny |
| Guest model lock | Guest + model ≠ phi3:mini | Deny |
| Analyst rate cap | Analyst + > 20 req/min | Deny |
| Code exec gate | Analyst + code keywords in prompt | Deny |

---

## Testing

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest tests/ -q          # unit/integration tests
.venv/bin/pytest tests/attacks/ -q  # attack simulation suite
```

> Integration tests obtain normal tokens from the local demo endpoint. Keep
> `ENABLE_DEMO_TOKEN_ENDPOINT=true` only in local development; production
> deployments should issue JWTs through their identity provider.

---

## Project structure

```
sentinel/
├── gateway/
│   ├── main.py              # FastAPI app — 11-stage pipeline (v2)
│   ├── config.py            # Environment configuration
│   ├── context.py           # RequestContext, HopRecord, Finding
│   ├── backends/
│   │   ├── classifier.py    # Intent/complexity classifier (Hop 1) — NEW
│   │   └── ollama.py        # LLM backend (v2: per-hop metrics)
│   ├── scanning/
│   │   ├── pii.py           # Two-layer PII scan (v2: regex + Presidio)
│   │   ├── injection.py     # 51 patterns + token-split heuristic
│   │   ├── risk.py          # Capped risk aggregation
│   │   ├── output.py        # Secret patterns + entropy
│   │   ├── sanitize.py      # NFKC + homoglyph normalization
│   │   └── cost.py          # Token estimation + shadow cost — NEW
│   ├── policy/
│   │   ├── opa_client.py    # OPA query (fail-closed)
│   │   └── router.py        # Classifier-aware model routing (v2)
│   ├── middleware/          # auth (JWT), rate_limit
│   └── observability/
│       ├── metrics.py       # 16 Prometheus metrics (v2)
│       └── logger.py        # JSONL audit log with per-hop timing (v2)
├── opa/policies/            # sentinel.rego + tests
├── presidio/                # PII microservice
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/dashboards/sentinel.json   # v2: 16 panels
├── research/
│   ├── run_benchmark.py
│   ├── analyze_logs.py      # Anti-pattern mining — NEW
│   ├── benchmark_dataset.json
│   └── results/
├── docs/
│   └── positioning.md       # Research framing + preprint roadmap
├── tests/
├── sentinel_ui.html
├── sentinel_trace.html
└── docker-compose.yml
```

---

## Research framing

See [`docs/positioning.md`](docs/positioning.md) for how SENTINEL maps onto the
FMware-operations research agenda:

| Research axis | SENTINEL instantiation |
|---------------|----------------------|
| Operationalizing FM models | Auth, policy, routing, monitoring, fail-closed handling |
| Software performance engineering | Per-hop latency/cost; FM backend dominates by 3–4 orders of magnitude |
| Monitoring & debugging distributed systems | 6-service stack, Prometheus/Grafana, per-hop trace, structured audit logs |
| Software analytics | Privacy-preserving JSONL logs → anti-pattern catalogue |
| Software visualization | Per-hop latency/cost Grafana panels; trace endpoint for compound pipelines |

---

*SENTINEL v2.0.0 — research / educational use.*
