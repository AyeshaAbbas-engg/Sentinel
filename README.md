# SENTINEL

A zero-trust security gateway for Large Language Models. SENTINEL sits between clients and any LLM backend, enforcing a 10-layer inspection pipeline on every request and response.

```
User Request
     │
     ▼
┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
│ Layer 1 │→ │  Layer 2  │→ │ Layer 3  │→ │ Layer 4  │→ │   Layer 5   │
│JWT Auth │  │Rate Limit │  │Sanitize  │  │PII Scan  │  │Injection Det│
└─────────┘  └───────────┘  └──────────┘  └──────────┘  └─────────────┘
                                                               │
                                                               ▼
┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
│Layer 10 │← │  Layer 9  │← │ Layer 8  │← │ Layer 7  │← │   Layer 6   │
│Output   │  │LLM Backend│  │Model Route│  │OPA Policy│  │ Risk Score  │
└─────────┘  └───────────┘  └──────────┘  └──────────┘  └─────────────┘
     │
     ▼
User Response
```

## Features

- **Prompt injection detection** — 38 regex patterns across 4 severity levels plus token-split analysis
- **PII scanning** — Microsoft Presidio integration detecting 8 entity types (email, SSN, credit card, etc.)
- **Policy-as-code** — Open Policy Agent with Rego rules for role-based access control
- **Risk scoring** — Continuous 0.0–1.0 threat signal with per-scanner caps
- **Output scanning** — Secret detection and Shannon entropy analysis on LLM responses
- **Rate limiting** — Sliding-window per-user limits by role
- **Model-agnostic** — Works with any LLM backend (Ollama, OpenAI, Anthropic, etc.)
- **Fail-closed** — Service failures deny requests; security is never silently bypassed
- **Full observability** — Prometheus metrics, Grafana dashboards, structured JSONL audit logs

## Architecture

| Service | Port | Technology | Role |
|---------|------|------------|------|
| Gateway | 8000 | FastAPI / Uvicorn | Core security pipeline |
| Presidio | 8001 | Microsoft Presidio / spaCy | PII detection |
| OPA | 8181 | Open Policy Agent | Policy decisions |
| Ollama | 11434 | Ollama | Local LLM backend |
| Prometheus | 9090 | Prometheus | Metrics collection |
| Grafana | 3000 | Grafana | Monitoring dashboards |

## Quick Start

### Prerequisites

- Docker and Docker Compose
- 4 GB+ RAM (for LLM model loading)

### Setup

```bash
# Configure environment
cp .env.example .env
# Edit .env and set a strong JWT_SECRET

# Start all services
docker compose up --build

# Pull an LLM model (first run only)
docker compose exec ollama ollama pull phi3:mini

# Generate test tokens
python gateway/generate_token.py
```

### Usage

```bash
# Send a request
curl -X POST http://localhost:8000/v1/chat \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is zero-trust security?", "model": "phi3:mini"}'

# Health check
curl http://localhost:8000/health

# View metrics
curl http://localhost:8000/metrics
```

Open `sentinel_ui.html` in a browser for the interactive web UI.

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/chat` | JWT | Main chat endpoint (full pipeline) |
| POST | `/token` | None | Generate demo JWT tokens |
| GET | `/health` | None | Deep health check (pings all services) |
| GET | `/metrics` | None | Prometheus metrics |
| GET | `/docs` | None | Swagger UI |

### Request

```json
{
  "prompt": "What is zero-trust security?",
  "model": "phi3:mini"
}
```

### Response (allowed)

```json
{
  "request_id": "f18dd22e-ad20-499b-8bc3-fdecdc4f1953",
  "response": "Zero trust security is...",
  "model_used": "phi3:mini",
  "risk_score": 0.0,
  "risk_level": "low",
  "policy_decision": "allow",
  "pii_detected": false,
  "injection_detected": false,
  "output_flagged": false
}
```

### Response (blocked)

```json
{
  "detail": {
    "reason": "risk score 0.80 exceeds threshold 0.7",
    "risk_score": 0.8,
    "injection_detected": true,
    "pii_detected": false
  }
}
```

## Security Pipeline

| Layer | Component | Function |
|-------|-----------|----------|
| 1 | JWT Auth | Verifies identity via HS256 tokens; extracts user_id and role |
| 2 | Rate Limit | Sliding-window limits: admin 60/min, analyst 20/min, guest 5/min |
| 3 | Sanitize | NFKC normalization, homoglyph replacement, zero-width stripping |
| 4 | PII Scan | Presidio NLP detection with circuit breaker (fail-closed) |
| 5 | Injection | 38 patterns + token-split detection across critical/high/medium/low |
| 6 | Risk Score | Aggregates findings into 0.0–1.0 score with per-scanner caps |
| 7 | OPA Policy | Rego rules enforce RBAC, risk thresholds, model restrictions |
| 8 | Model Route | Selects LLM tier based on role × risk level |
| 9 | LLM Backend | Forwards sanitized prompt to Ollama (timeout/error handling) |
| 10 | Output Scan | Secret pattern matching + Shannon entropy analysis on responses |

## Policy Rules

Defined in `opa/policies/sentinel.rego`:

| Rule | Condition | Action |
|------|-----------|--------|
| Risk hard block | risk_score > 0.7 | Deny all roles |
| PII restriction | PII detected + role ≠ admin | Deny |
| Guest model lock | Guest + model ≠ phi3:mini | Deny |
| Analyst rate cap | Analyst + >20 req/min | Deny |
| Code exec gate | Analyst + code keywords | Deny |

## Configuration

All settings via environment variables (see `.env.example`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | Yes | — | Token signing key |
| `OLLAMA_URL` | No | `http://ollama:11434` | LLM backend |
| `PRESIDIO_URL` | No | `http://presidio:8001` | PII service |
| `OPA_URL` | No | `http://opa:8181` | Policy engine |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` | CORS whitelist (comma-separated) |
| `MAX_PROMPT_LENGTH` | No | `4096` | Max input characters |
| `RATE_LIMIT_ADMIN` | No | `60` | Admin requests/min |
| `RATE_LIMIT_ANALYST` | No | `20` | Analyst requests/min |
| `RATE_LIMIT_GUEST` | No | `5` | Guest requests/min |
| `OLLAMA_TIMEOUT` | No | `180` | LLM timeout (seconds) |

The gateway refuses to start if `JWT_SECRET` is not set.

## Monitoring

- **Grafana**: http://localhost:3000 (admin / sentinel)
- **Prometheus**: http://localhost:9090

### Exported Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sentinel_requests_total` | Counter | Requests by role and decision |
| `sentinel_requests_blocked_total` | Counter | Blocks by reason |
| `sentinel_risk_score` | Histogram | Risk score distribution |
| `sentinel_pii_detections_total` | Counter | PII detections by entity type |
| `sentinel_request_latency_ms` | Histogram | End-to-end latency |
| `sentinel_model_requests_total` | Counter | Requests per model |

### Audit Logs

Structured JSONL at `gateway/logs/audit.jsonl`. Prompts stored as SHA-256 hashes (privacy-preserving). Rotating files: 10 MB × 5 backups.

## Testing

```bash
# Run unit/integration tests
pytest tests/

# Run attack simulation suite
pytest tests/attacks/
```

## Project Structure

```
sentinel/
├── gateway/
│   ├── main.py              # FastAPI app — pipeline orchestration
│   ├── config.py            # Environment configuration
│   ├── context.py           # Request context dataclass
│   ├── generate_token.py    # JWT token generator
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── backends/
│   │   └── ollama.py        # LLM client
│   ├── middleware/
│   │   ├── auth.py          # JWT verification
│   │   └── rate_limit.py    # Sliding-window rate limiter
│   ├── scanning/
│   │   ├── sanitize.py      # Unicode normalization
│   │   ├── pii.py           # PII detection (Presidio)
│   │   ├── injection.py     # Prompt injection detection
│   │   ├── risk.py          # Risk score aggregation
│   │   └── output.py        # Response secret scanning
│   ├── policy/
│   │   ├── opa_client.py    # OPA integration
│   │   └── router.py        # Model routing
│   └── observability/
│       ├── metrics.py       # Prometheus metrics
│       └── logger.py        # JSONL audit logger
├── opa/policies/
│   ├── sentinel.rego        # Authorization rules
│   └── sentinel_test.rego   # Policy unit tests
├── presidio/
│   ├── app.py               # PII microservice
│   └── Dockerfile
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/dashboards/
├── tests/
│   ├── test_auth.py
│   ├── test_policy.py
│   ├── test_inspection.py
│   └── attacks/
├── sentinel_ui.html         # Web UI
├── docker-compose.yml
└── .env.example
```

## OWASP LLM Top 10 Coverage

| # | Risk | Mitigation |
|---|------|------------|
| LLM01 | Prompt Injection | Layer 5 — 38 patterns + token-split detection |
| LLM02 | Insecure Output | Layer 10 — secret scanning + entropy analysis |
| LLM04 | Model DoS | Layer 2 — role-based rate limiting |
| LLM06 | Sensitive Disclosure | Layer 4 (PII) + Layer 10 (secrets) |
| LLM08 | Excessive Agency | Layer 7 — OPA policy restricts capabilities |
| LLM10 | Model Theft | Layer 1 (auth) + Layer 7 (access control) |

## License

This project is for research and educational purposes.
