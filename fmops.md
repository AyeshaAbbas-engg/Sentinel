# SENTINEL → FMware-Ops — What We're Building (Phase 1)

*This is the historical Phase-1 design record. The implementation has progressed
beyond it: the two-hop pipeline, per-hop cost telemetry, classifier-aware OPA
governance, trace visualization, and log analytics are now present. It is kept
for design rationale; use [`README.md`](README.md) and the current source for the
shipped behavior. It is the
engineering companion to [`docs/positioning.md`](docs/positioning.md) (the research
framing) and [`README.md`](README.md) (the shipped state). Scope here is **Phase 1
only** — the multi-model, two-hop inference pipeline — with the later phases
sketched for context.*

---

## 1. One-line intent

> Turn SENTINEL's **single-hop** inference path into an opt-in **multi-model,
> two-hop** pipeline — *classify → select → generate* — and instrument **every
> hop** for latency and token cost, so one end-to-end latency number becomes a
> per-hop breakdown.

This is the first concrete step from *"a gateway that governs one model"* toward
*"an operational control plane for compound (multi-model, multi-hop) FMware"*: a
control plane's value is to **see, attribute, and route around** foundation-model
cost and unreliability — not merely to block bad requests.

---

## 2. Where this sits in the roadmap

| Phase | Status | What it delivers |
|-------|--------|------------------|
| 0 — Reposition + integrity cleanup | ✅ done | Honest reports, FMware framing, corrected counts |
| **1 — Multi-model 2-hop pipeline** | ✅ done | Classifier hop → model selection → generation hop; per-hop latency + tokens |
| 2 — Per-hop governance + cost instrumentation | ✅ done | Classifier-aware OPA policy, real Ollama tokens, and shadow-cost attribution |
| 3 — Per-hop monitoring + visualization | ✅ done | Trace endpoint + Grafana panels showing where time/cost go per hop |
| 4 — Log analytics + anti-pattern catalogue | ✅ done | Audit-log mining for eight operational anti-patterns |
| 5 — Preprint + SOI | later | Write-up of the compound-FMware control plane |

---

## 3. Locked design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Classifier hop mechanism | **LLM classifier, capped output** (`num_predict≈5`, `temperature=0`) | Authentic compound-FMware "LLM-as-router" pattern; a 1–2 token SIMPLE/COMPLEX call is cheap even on CPU (the 68 s latencies come from full generations, not 1-token calls). |
| Second model | **`qwen2.5:1.5b`** | ~1 GB, fast on CPU. Serves as **both** the classifier **and** the "cheap/simple" generation tier. `phi3:mini` (3.8B) stays as the "standard/complex" tier. Two models total, one new pull. |
| Activation | **Opt-in via `model:"auto"`** | Any explicit model keeps today's single-hop path **byte-for-byte**. Preserves existing tests + the v1.1.0 benchmark baseline, and enables a clean single-hop-vs-2-hop comparison on the same dataset. |
| Per-hop token capture | **In scope for Phase 1** | Ollama already returns `eval_count`/`prompt_eval_count`/durations; we currently throw them away. Capturing them now is nearly free and is the substrate for the Phase 2 cost model. |

---

## 4. Current state — the single hop (what exists today)

In `gateway/main.py`, `POST /v1/chat` runs the 10-stage pipeline. The inference
stage is exactly two adjacent lines:

```
main.py:192   routing = resolve_model(ctx.role, ctx.risk_score, decision["model_route"])
main.py:195   raw_response = await call_ollama(ctx.clean_prompt, routing.model)
```

Consequences of the current shape:

- `gateway/policy/router.py` — `AVAILABLE_MODELS = {"phi3:mini": "phi3:mini"}` (single entry).
- `gateway/backends/ollama.py` — `call_ollama(prompt, model) -> str` returns only
  `response.json()["response"]` and **discards** `eval_count`, `prompt_eval_count`,
  `eval_duration`, `prompt_eval_duration`, `total_duration`. It passes **no**
  generation options.
- `gateway/context.py` — `RequestContext` holds **single-valued** `model_used` and
  `latency_ms`, one flat `findings` list, one `risk_score`. **No per-hop containers.**
- `gateway/config.py` — has **no** model-name constant; model strings live only in
  `ChatRequest.model` default and `router.py`.
- The `/v1/chat/trace` endpoint is the *only* place an LLM hop is individually timed
  (`llm_ms`), and that number is never stored or recorded.

---

## 5. Target state — two hops (auto mode)

```
POST /v1/chat  {"prompt": "...", "model": "auto"}
        │
        ▼
  [ Stages 1–7: auth → rate-limit → sanitize → PII → injection → risk → OPA ]   ← unchanged, runs ONCE, fail-closed
        │  (OPA sees requested_model = "phi3:mini" in auto mode — see §9)
        ▼
  ┌──────────────────────────── HOP 1: CLASSIFY ────────────────────────────┐
  │ call_ollama(clean_prompt, qwen2.5:1.5b, options={num_predict:5, temp:0}) │
  │   → label ∈ {SIMPLE, COMPLEX}                                            │
  │   → record HopRecord("classify", model, latency_ms, tokens)             │
  └─────────────────────────────────────────────────────────────────────────┘
        │
        ▼
  [ MODEL SELECTION ]  select_generation_model(label, role)
        guest            → phi3:mini        (policy pin)
        SIMPLE (non-guest)→ qwen2.5:1.5b    (cheap tier)
        COMPLEX          → phi3:mini        (standard tier)
        │
        ▼
  ┌──────────────────────────── HOP 2: GENERATE ────────────────────────────┐
  │ call_ollama(clean_prompt, selected_model)                               │
  │   → raw_response (user-facing)                                          │
  │   → record HopRecord("generate", model, latency_ms, tokens)            │
  └─────────────────────────────────────────────────────────────────────────┘
        │
        ▼
  [ Stage 10: output scan (hop-2 response only) ] → ChatResponse + per-hop telemetry
```

**Explicit mode** (`model` is any real model string, e.g. `"phi3:mini"`): no classify
hop; the single generation call runs exactly as today. For uniform analytics it
still records **one** `HopRecord("generate", …)`.

---

## 6. The two models

| Tier | Model | Size | Role in the pipeline |
|------|-------|------|----------------------|
| Classifier | `qwen2.5:1.5b` | ~1 GB | Hop 1 — SIMPLE/COMPLEX label, capped output |
| Cheap / simple | `qwen2.5:1.5b` | ~1 GB | Hop 2 when label = SIMPLE (non-guest) |
| Standard / complex | `phi3:mini` | ~3.8B | Hop 2 when label = COMPLEX, or guest, or classifier failure |

`qwen2.5:1.5b` must be pulled into Ollama: `docker compose exec ollama ollama pull qwen2.5:1.5b`.

---

## 7. File-by-file changes (dependency order)

### 7.1 `gateway/config.py` — centralize model names *(modify)*
Add env-backed constants (no hard-coded strings scattered around):
```python
CLASSIFIER_MODEL = os.getenv("CLASSIFIER_MODEL", "qwen2.5:1.5b")
CHEAP_MODEL      = os.getenv("CHEAP_MODEL", "qwen2.5:1.5b")
STANDARD_MODEL   = os.getenv("STANDARD_MODEL", "phi3:mini")
CLASSIFIER_MAX_TOKENS = int(os.getenv("CLASSIFIER_MAX_TOKENS", "5"))
```

### 7.2 `gateway/backends/ollama.py` — capture per-hop cost *(modify)*
Change the single backend function to return a small result object and accept options:
```python
@dataclass
class OllamaResult:
    response: str
    prompt_tokens: int          # from prompt_eval_count
    completion_tokens: int      # from eval_count
    total_duration_ns: int      # from total_duration
    eval_duration_ns: int       # from eval_duration

async def call_ollama(prompt: str, model: str, options: dict | None = None) -> OllamaResult:
    ...
    body = {"model": model, "prompt": prompt, "stream": False}
    if options:
        body["options"] = options          # e.g. {"num_predict": 5, "temperature": 0}
    ...
    data = response.json()
    return OllamaResult(
        response=data.get("response", ""),
        prompt_tokens=data.get("prompt_eval_count", 0),
        completion_tokens=data.get("eval_count", 0),
        total_duration_ns=data.get("total_duration", 0),
        eval_duration_ns=data.get("eval_duration", 0),
    )
```
- **Fail-closed behavior preserved exactly** (ReadTimeout→504, ConnectError→503, other→502).
- **Both call sites updated:** `main.py:195` (now reads `.response`) and the trace
  endpoint `main.py:~341` (reads `.response`; the existing `llm_ms` timing stays).

### 7.3 `gateway/policy/classifier.py` — HOP 1 *(new file)*
```python
async def classify_complexity(clean_prompt: str) -> tuple[str, OllamaResult]:
    """Returns (label, ollama_result). label ∈ {"SIMPLE","COMPLEX"}."""
```
Exact prompt:
```
You are a routing classifier. Reply with exactly ONE word — SIMPLE or COMPLEX —
for how much reasoning the request below needs.
SIMPLE = short factual lookup, definition, or casual chat.
COMPLEX = multi-step reasoning, coding, analysis, or long-form writing.

Request:
"""{prompt}"""

Answer:
```
Call: `call_ollama(prompt, CLASSIFIER_MODEL, {"num_predict": CLASSIFIER_MAX_TOKENS, "temperature": 0})`.
Parse (robust): uppercase the response; if it contains `"COMPLEX"` → `COMPLEX`;
elif it contains `"SIMPLE"` → `SIMPLE`; else **default `COMPLEX`** (fail safe toward
the stronger model). On `HTTPException` from the classifier call → **also `COMPLEX`**
(degrade, don't deny — see §9).

### 7.4 `gateway/policy/router.py` — model selection *(modify)*
- `AVAILABLE_MODELS` gains `"qwen2.5:1.5b": "qwen2.5:1.5b"`.
- New function:
```python
def select_generation_model(label: str, role: str) -> RoutingDecision:
    if role == "guest":
        return RoutingDecision(STANDARD_MODEL, "guest_pinned", "Guest pinned to standard tier")
    if label == "SIMPLE":
        return RoutingDecision(CHEAP_MODEL, "auto_simple", "Classified SIMPLE → cheap tier")
    return RoutingDecision(STANDARD_MODEL, "auto_complex", "Classified COMPLEX → standard tier")
```
- `resolve_model(...)` (single-hop / explicit path) is left unchanged.

### 7.5 `gateway/context.py` — per-hop container *(modify)*
```python
@dataclass
class HopRecord:
    hop_index: int
    name: str                 # "classify" | "generate"
    model: str
    latency_ms: int
    prompt_tokens: int = 0
    completion_tokens: int = 0
```
Add to `RequestContext`: `hops: list = field(default_factory=list)` and
`classification: str = ""`. **Keep** `model_used` (= hop-2/generation model) and
`latency_ms` (= total) for backward compatibility with logger/metrics.

### 7.6 `gateway/main.py` — orchestration *(modify)*
- `ChatResponse` gains three **optional** keys (existing 15 keys untouched):
  `routing_mode: str` (`"explicit"|"auto"`), `classification: str | None`,
  `hops: list` (list of `HopRecord` as dicts).
- In `chat(...)`, after OPA allows (line ~189), branch on `request.model == "auto"`:
  - **auto:** time & run `classify_complexity` → append classify `HopRecord`;
    `routing = select_generation_model(label, ctx.role)`; time & run the generation
    `call_ollama(ctx.clean_prompt, routing.model)` → append generate `HopRecord`.
  - **explicit:** `routing = resolve_model(...)` then one `call_ollama` as today;
    append one generate `HopRecord`.
  - Both set `ctx.model_used = routing.model`, `ctx.latency_ms` = total.
- OPA ordering handled in §9.

### 7.7 `gateway/observability/metrics.py` — minimal per-hop seam *(modify)*
Add one labeled histogram + helper, following the existing pattern:
```python
hop_latency_ms = Histogram("sentinel_hop_latency_ms", "Per-hop latency", ["hop", "model"], buckets=[...])
def record_hop(hop: str, model: str, latency_ms: int):
    hop_latency_ms.labels(hop=hop, model=model).observe(latency_ms)
```
Reuse `record_model(model)` for the classifier model too. (Full Grafana panels +
cost/pricing metrics = Phase 2/3.)

### 7.8 `gateway/observability/logger.py` — audit trail *(modify)*
Add a `"hops"` array to the log entry (list of `{hop_index, name, model,
latency_ms, prompt_tokens, completion_tokens}`) alongside the existing single-scalar
`model_used`/`total_latency_ms` (kept for backward compat).

### 7.9 `docker-compose.yml` / `README.md` — model availability *(modify)*
Document `docker compose exec ollama ollama pull qwen2.5:1.5b` in Quick Start and
the roadmap "done" note; keep phi3:mini pull as-is.

### 7.10 `research/run_benchmark.py` — comparison pass *(modify, light)*
Add a `--auto` flag (or a second pass) that resends the dataset with `model:"auto"`,
so single-hop vs 2-hop can be compared on the same prompts. Deep analytics is Phase 4;
this is just the data-collection hook.

---

## 8. New / changed data shapes (summary)

**`OllamaResult`** (new, `backends/ollama.py`): `response, prompt_tokens, completion_tokens, total_duration_ns, eval_duration_ns`.

**`HopRecord`** (new, `context.py`): `hop_index, name, model, latency_ms, prompt_tokens, completion_tokens`.

**`RequestContext`** (add): `hops: list`, `classification: str`. (Keep `model_used`, `latency_ms`.)

**`ChatResponse`** (add, optional): `routing_mode`, `classification`, `hops`. (Keep all 15 existing keys; `model_used` = generation model.)

---

## 9. Key edge cases & the decisions we made

**A. OPA runs *before* the model is known.** `query_opa` executes at `main.py:175`,
before selection at `:192`. The rego **guest model-lock** rule denies
`guest + model != phi3:mini`. In auto mode we don't yet know the generation model.
**Phase-1 approach:** when `model=="auto"`, pass the always-allowed standard tier
`"phi3:mini"` to `query_opa`, so existing policy (incl. guest lock) is satisfied;
*after* OPA allows, run classify → select, and **pin guests to `phi3:mini`**. Governing
each hop's model *independently* is explicitly **Phase 2**.

**B. Classifier failure = degrade, not deny.** The request has already passed **all**
security gates before hop 1. Model *selection* is an optimization, not a security
control. So a classifier timeout/error **falls back to the standard tier
(`phi3:mini`)** with a logged note — it does **not** raise 403/503. This is a
deliberate, documented divergence from the otherwise fail-closed ethos, scoped to
*routing only*. The **generation hop keeps** today's fail-closed 5xx behavior.

**C. Classifier output is a control signal, not user content.** The label is never
returned to the user and is **not** run through `scan_output`. The classifier sees the
already-sanitized/PII-scanned/injection-scanned `clean_prompt`, so residual injection
risk into the classifier is low and its constrained output (≤5 tokens, parsed to a
label) cannot carry an exfiltration payload. Only the **hop-2 generation** output is
output-scanned, exactly as today.

**D. Backward compatibility is a hard requirement.** Explicit mode reproduces today's
single-hop path exactly — same `ChatResponse` values, same metrics, same audit fields.
The new keys are additive and optional.

---

## 10. Tests (in `tests/`, using existing `conftest.py` fixtures)

Mock `call_ollama` (e.g. `monkeypatch`) so tests never hit a live Ollama; return a
crafted `OllamaResult`.

| File | Test | Asserts |
|------|------|---------|
| `test_classifier.py` (new) | `test_parse_complex` / `test_parse_simple` | Label parsing from noisy model output |
| `test_classifier.py` | `test_classifier_failure_defaults_complex` | Backend `HTTPException` → `COMPLEX` (degrade) |
| `test_routing_auto.py` (new) | `test_auto_two_hops` | `ctx.hops` has exactly 2 records, names `classify`/`generate`, correct models |
| `test_routing_auto.py` | `test_auto_guest_pinned` | Guest in auto mode → generation model `phi3:mini` |
| `test_routing_auto.py` | `test_explicit_single_hop` | Explicit model → 1 hop, response identical to today |
| `test_ollama_result.py` (new) | `test_token_capture` | `OllamaResult` populates prompt/completion tokens |

---

## 11. Verification — end to end

```bash
# 1. Bring up the stack and pull both models
docker compose up --build -d
docker compose exec ollama ollama pull phi3:mini
docker compose exec ollama ollama pull qwen2.5:1.5b

# 2. Token
TOKEN=$(curl -s -X POST localhost:8000/token -d '{"user_id":"u","role":"admin"}' -H 'Content-Type: application/json' | jq -r .access_token)

# 3a. Explicit mode — must look exactly like v1.1.0 (single hop)
curl -s -X POST localhost:8000/v1/chat -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"prompt":"What is a foundation model?","model":"phi3:mini"}' | jq

# 3b. Auto mode — expect routing_mode:"auto", a classification label, and hops[] with 2 entries
curl -s -X POST localhost:8000/v1/chat -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"prompt":"Hi there","model":"auto"}' | jq '.routing_mode, .classification, .hops'

# 4. Confirm per-hop telemetry landed
tail -n1 gateway/logs/audit.jsonl | jq '.hops'          # per-hop models/latency/tokens
curl -s localhost:8000/metrics | grep sentinel_hop_latency_ms

# 5. Tests
pytest tests/ -k "classifier or routing_auto or ollama_result"

# 6. Single-hop vs 2-hop comparison data
python3 research/run_benchmark.py            # baseline (explicit phi3:mini)
python3 research/run_benchmark.py --auto     # 2-hop auto path
```

**Success criteria:** explicit-mode response is unchanged; auto-mode returns two
`HopRecord`s with distinct per-hop latency and token counts; guests always generate on
`phi3:mini`; a simulated classifier outage still produces a valid `phi3:mini` answer
(no 5xx); audit log and `sentinel_hop_latency_ms` show per-hop data.

---

## 12. Explicitly deferred (NOT in Phase 1)

- **Per-hop OPA governance** — policy evaluated independently at each hop (Phase 2).
- **Cost/pricing model + cost metrics + Grafana per-hop panels** (Phase 2/3).
- **Deep trace-endpoint per-hop rework** beyond the minimal `call_ollama` return-type
  update needed to keep it working (Phase 3).
- **Anti-pattern log mining** — redundant hops, timeout cascades, cost blowups on
  low-value requests (Phase 4).
- **Unrelated rough edges** — CORS `["*"]` lockdown, test/`.env` secret alignment,
  dead `should_block()` removal.
