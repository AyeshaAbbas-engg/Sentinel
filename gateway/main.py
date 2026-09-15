import uuid
import time
import collections
import threading
import httpx
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException, Response
from pydantic import BaseModel, field_validator
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from datetime import datetime, timedelta, timezone

from config import (
    JWT_SECRET, JWT_ALGORITHM, ALLOWED_ORIGINS, MAX_PROMPT_LENGTH,
    OLLAMA_URL, PRESIDIO_URL, OPA_URL, STANDARD_MODEL, ENABLE_DEMO_TOKEN_ENDPOINT,
)
from context import RequestContext
from middleware.auth import verify_jwt
from middleware.rate_limit import check_rate_limit, get_request_count
from observability.logger import log_request
from observability.metrics import (
    record_request, record_block, record_pii,
    record_injection, record_model, record_output_flag,
    record_hop, record_classifier, record_tokens_and_cost,
)
from scanning.pii import scan_pii
from scanning.injection import scan_injection
from scanning.sanitize import normalize_text
from scanning.risk import compute_risk_score, get_risk_level
from scanning.output import scan_output
from scanning.cost import estimate_cost
from policy.opa_client import query_opa
from policy.router import resolve_model
from backends.ollama import call_ollama
from backends.classifier import classify, classify_llm

app = FastAPI(title="SENTINEL Gateway", version="2.0.0")


# ── CORS ──────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── In-memory hop stats ring buffer ──────────────────────
# Stores last N HopRecord lists for /v1/pipeline/hops stats.
_HOP_RING_SIZE = 500
_hop_ring: collections.deque = collections.deque(maxlen=_HOP_RING_SIZE)
_hop_ring_lock = threading.Lock()

def _record_hop_ring(hop_timings: list):
    with _hop_ring_lock:
        _hop_ring.append([
            {"name": h.name, "latency_ms": h.latency_ms, "status": h.status}
            for h in hop_timings
        ])

# ── Ordered pipeline stage definitions ───────────────────
PIPELINE_STAGES = [
    {"step": 1,  "name": "jwt_auth",         "layer": "access"},
    {"step": 2,  "name": "rate_limit",        "layer": "access"},
    {"step": 3,  "name": "sanitize",          "layer": "input"},
    {"step": 4,  "name": "pii_scan",          "layer": "input"},
    {"step": 5,  "name": "injection_scan",    "layer": "input"},
    {"step": 6,  "name": "risk_score",        "layer": "input"},
    {"step": 7,  "name": "classifier",        "layer": "routing"},
    {"step": 8,  "name": "opa_policy",        "layer": "routing"},
    {"step": 9,  "name": "model_routing",     "layer": "routing"},
    {"step": 10, "name": "llm_backend",       "layer": "inference"},
    {"step": 11, "name": "output_scan",       "layer": "output"},
]


# ── Request / Response Models ─────────────────────────────

class ChatRequest(BaseModel):
    prompt: str
    model: str = "phi3:mini"

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Prompt cannot be empty")
        if len(v) > MAX_PROMPT_LENGTH:
            raise ValueError(f"Prompt exceeds maximum length of {MAX_PROMPT_LENGTH} characters")
        return v


class ChatResponse(BaseModel):
    request_id: str
    response: str
    model_used: str
    routing_tier: str
    routing_reason: str
    routing_mode: str
    complexity_tier: str
    intent_class: str
    risk_score: float
    risk_level: str
    user_id: str
    role: str
    pii_detected: bool
    pii_entities: list
    injection_detected: bool
    output_flagged: bool
    policy_decision: str
    policy_reason: str
    latency_ms: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float


class TokenRequest(BaseModel):
    user_id: str
    role: str


class TokenResponse(BaseModel):
    access_token: str
    role: str
    user_id: str
    expires_in: int
    issued_at: str


# ── Metrics Endpoint ──────────────────────────────────────

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── Health Check ──────────────────────────────────────────

@app.get("/health")
async def health():
    checks = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, url in [
            ("presidio", f"{PRESIDIO_URL}/health"),
            ("opa",      f"{OPA_URL}/health"),
            ("ollama",   f"{OLLAMA_URL}"),
        ]:
            try:
                r = await client.get(url)
                checks[name] = "ok" if r.status_code < 400 else "degraded"
            except Exception:
                checks[name] = "unreachable"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {
        "status":       overall,
        "service":      "sentinel-gateway",
        "version":      "2.0.0",
        "dependencies": checks,
        "pipeline":     [s["name"] for s in PIPELINE_STAGES],
    }


# ── Token Endpoint (demo) ─────────────────────────────────

@app.post("/token", response_model=TokenResponse)
async def generate_token(req: TokenRequest):
    if not ENABLE_DEMO_TOKEN_ENDPOINT:
        raise HTTPException(
            status_code=404,
            detail="Demo token endpoint is disabled; use your identity provider",
        )
    if req.role not in ["admin", "analyst", "guest"]:
        raise HTTPException(status_code=400, detail="Role must be admin, analyst, or guest")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=60)
    payload = {"sub": req.user_id, "role": req.role, "iat": now, "exp": exp}
    from jose import jwt as jose_jwt
    token = jose_jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return TokenResponse(
        access_token=token, role=req.role, user_id=req.user_id,
        expires_in=3600, issued_at=now.isoformat()
    )


# ── V1 Chat Endpoint ──────────────────────────────────────

@app.post("/v1/chat", response_model=ChatResponse)
@app.post("/chat",    response_model=ChatResponse, include_in_schema=False)
async def chat(request: ChatRequest, claims: dict = Depends(verify_jwt)):
    pipeline_start = time.perf_counter()

    ctx = RequestContext(
        request_id=str(uuid.uuid4()),
        user_id=claims["user_id"],
        role=claims["role"],
        raw_prompt=request.prompt,
        clean_prompt=request.prompt,
    )

    def elapsed_ms() -> int:
        return max(1, int((time.perf_counter() - pipeline_start) * 1000))

    # ── Routing mode ─────────────────────────────────────
    # "auto"   → compound 2-hop pipeline: an LLM classifier hop picks the
    #            generation model (cheap model for simple/moderate prompts).
    # "explicit" → single generation call on the requested model (back-compat).
    mode = "auto" if request.model == "auto" else "explicit"
    # In auto mode we present STANDARD_MODEL to OPA so the guest-lock rule
    # (requested_model == "phi3:mini") is satisfied before model selection.
    opa_model = STANDARD_MODEL if mode == "auto" else request.model

    # ── Layer 2: Rate Limiting ───────────────────────────
    t = time.perf_counter()
    check_rate_limit(ctx.user_id, ctx.role)
    ctx.requests_last_minute = get_request_count(ctx.user_id)
    ctx.record_hop("rate_limit", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("rate_limit", ctx.hop_timings[-1].latency_ms)

    # ── Layer 3: Input Sanitization ──────────────────────
    t = time.perf_counter()
    ctx.clean_prompt = normalize_text(ctx.clean_prompt)
    ctx.record_hop("sanitize", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("sanitize", ctx.hop_timings[-1].latency_ms)

    # ── Layer 4: PII Scan ────────────────────────────────
    t = time.perf_counter()
    ctx = await scan_pii(ctx)
    ctx.record_hop("pii_scan", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("pii_scan", ctx.hop_timings[-1].latency_ms)

    # ── Layer 5: Injection Scan ──────────────────────────
    t = time.perf_counter()
    ctx = scan_injection(ctx)
    ctx.record_hop("injection_scan", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("injection_scan", ctx.hop_timings[-1].latency_ms)

    # ── Layer 6: Risk Aggregation ────────────────────────
    t = time.perf_counter()
    ctx = compute_risk_score(ctx)
    ctx.record_hop("risk_score", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("risk_score", ctx.hop_timings[-1].latency_ms)

    # ── Layer 7: Classifier (Hop 1 — pre-LLM routing) ───
    # auto mode → real capped LLM classifier; explicit → fast heuristic.
    if mode == "auto":
        clf = await classify_llm(ctx.clean_prompt)
    else:
        clf = classify(ctx.clean_prompt)
    ctx.complexity_tier = clf.complexity_tier
    ctx.intent_class    = clf.intent_class

    # If the classifier hop actually called a model (auto mode, no fallback),
    # attribute its real tokens + shadow cost — genuine per-hop cost.
    clf_cost = None
    if clf.input_tokens or clf.output_tokens:
        clf_cost = estimate_cost(
            clf.model, "", "",
            prompt_tokens=clf.input_tokens,
            completion_tokens=clf.output_tokens,
        )
    ctx.record_hop(
        "classifier", clf.latency_ms,
        model=clf.model,
        input_tokens=clf.input_tokens,
        output_tokens=clf.output_tokens,
        estimated_cost_usd=(clf_cost.total_cost_usd if clf_cost else 0.0),
    )
    record_hop("classifier", clf.latency_ms)
    record_classifier(clf.complexity_tier, clf.intent_class)
    if clf_cost:
        ctx.input_tokens       += clf_cost.input_tokens
        ctx.output_tokens      += clf_cost.output_tokens
        ctx.estimated_cost_usd += clf_cost.total_cost_usd
        record_tokens_and_cost(clf_cost.input_tokens, clf_cost.output_tokens, clf_cost.total_cost_usd)


    # ── Layer 8: OPA Policy Decision ─────────────────────
    t = time.perf_counter()
    decision = await query_opa(ctx, opa_model)
    ctx.record_hop("opa_policy", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("opa_policy", ctx.hop_timings[-1].latency_ms)

    if not decision["allow"]:
        ctx.policy_decision = "block"
        ctx.policy_reason   = decision["reason"]
        ctx.latency_ms      = elapsed_ms()
        record_request(ctx.role, "block", ctx.risk_score, ctx.latency_ms)
        record_block(decision["reason"])
        log_request(ctx)
        _record_hop_ring(ctx.hop_timings)
        raise HTTPException(status_code=403, detail={
            "reason":             decision["reason"],
            "risk_score":         round(ctx.risk_score, 2),
            "injection_detected": any(f.scanner == "injection" for f in ctx.findings),
            "pii_detected":       any(f.scanner == "pii"       for f in ctx.findings),
        })

    # ── Layer 9: Model Routing ───────────────────────────
    t = time.perf_counter()
    routing = resolve_model(
        ctx.role, ctx.risk_score, decision["model_route"],
        ctx.complexity_tier, ctx.intent_class,
        mode=mode, requested_model=request.model,
    )
    ctx.record_hop("model_routing", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("model_routing", ctx.hop_timings[-1].latency_ms)

    # ── Layer 10: LLM Backend ─────────────────────────────
    raw_response, llm_ms, gen_pt, gen_ct = await call_ollama(ctx.clean_prompt, routing.model)

    # Cost attribution — real Ollama token counts for the generation hop.
    gen_cost = estimate_cost(
        routing.model, ctx.clean_prompt, raw_response,
        prompt_tokens=gen_pt, completion_tokens=gen_ct,
    )
    ctx.input_tokens       += gen_cost.input_tokens
    ctx.output_tokens      += gen_cost.output_tokens
    ctx.estimated_cost_usd += gen_cost.total_cost_usd

    ctx.record_hop(
        "llm_backend", llm_ms,
        model=routing.model,
        input_tokens=gen_cost.input_tokens,
        output_tokens=gen_cost.output_tokens,
        estimated_cost_usd=gen_cost.total_cost_usd,
    )
    record_hop("llm_backend", llm_ms)
    record_tokens_and_cost(gen_cost.input_tokens, gen_cost.output_tokens, gen_cost.total_cost_usd)

    # ── Layer 11: Output Scan ─────────────────────────────
    t = time.perf_counter()
    clean_response, output_blocked, output_findings = scan_output(ctx, raw_response)
    ctx.record_hop("output_scan", max(1, int((time.perf_counter() - t) * 1000)))
    record_hop("output_scan", ctx.hop_timings[-1].latency_ms)

    # ── Finalise Context ──────────────────────────────────
    ctx.model_used      = routing.model
    ctx.latency_ms      = elapsed_ms()
    ctx.policy_decision = "allow"
    ctx.policy_reason   = decision["reason"]

    # ── Prometheus ────────────────────────────────────────
    record_request(ctx.role, "allow", ctx.risk_score, ctx.latency_ms)
    record_model(routing.model)

    pii_findings = [f for f in ctx.findings if f.scanner == "pii"]
    if pii_findings:
        record_pii([f.description for f in pii_findings])

    injection_findings = [f for f in ctx.findings if f.scanner == "injection"]
    if injection_findings:
        record_injection(injection_findings)

    if output_blocked:
        record_output_flag("secret_detected")

    # ── Audit Log ─────────────────────────────────────────
    log_request(ctx)
    _record_hop_ring(ctx.hop_timings)

    # ── Response ──────────────────────────────────────────
    pii_entities = [f.description for f in ctx.findings if f.scanner == "pii"]

    return ChatResponse(
        request_id=ctx.request_id,
        response=clean_response,
        model_used=ctx.model_used,
        routing_tier=routing.tier,
        routing_reason=routing.reason,
        routing_mode=mode,
        complexity_tier=ctx.complexity_tier,
        intent_class=ctx.intent_class,
        risk_score=ctx.risk_score,
        risk_level=get_risk_level(ctx.risk_score),
        user_id=ctx.user_id,
        role=ctx.role,
        pii_detected=len(pii_entities) > 0,
        pii_entities=pii_entities,
        injection_detected=len(injection_findings) > 0,
        output_flagged=output_blocked,
        policy_decision=ctx.policy_decision,
        policy_reason=ctx.policy_reason,
        latency_ms=ctx.latency_ms,
        input_tokens=ctx.input_tokens,
        output_tokens=ctx.output_tokens,
        estimated_cost_usd=round(ctx.estimated_cost_usd, 8),
    )


# ── V1 Pipeline Hops Endpoint (Task 6) ───────────────────
# Returns pipeline topology + p50/p95 latency per hop from
# the last _HOP_RING_SIZE requests.  Used by Grafana and the
# /v1/chat/trace UI.

@app.get("/v1/pipeline/hops")
async def pipeline_hops():
    """
    Returns the static pipeline topology and live per-hop
    latency statistics computed from the in-memory ring buffer
    of the last 500 requests.
    """
    with _hop_ring_lock:
        snapshot = list(_hop_ring)

    # Build per-hop latency lists
    hop_latencies: dict[str, list[int]] = {}
    hop_statuses:  dict[str, dict[str, int]] = {}

    for request_hops in snapshot:
        for h in request_hops:
            name = h["name"]
            if name not in hop_latencies:
                hop_latencies[name] = []
                hop_statuses[name]  = {}
            hop_latencies[name].append(h["latency_ms"])
            status = h.get("status", "ok")
            hop_statuses[name][status] = hop_statuses[name].get(status, 0) + 1

    def percentile(data: list[int], p: float) -> int:
        if not data:
            return 0
        s = sorted(data)
        idx = max(0, int(len(s) * p / 100) - 1)
        return s[idx]

    hop_stats = []
    for stage in PIPELINE_STAGES:
        name = stage["name"]
        lats = hop_latencies.get(name, [])
        hop_stats.append({
            "step":       stage["step"],
            "name":       name,
            "layer":      stage["layer"],
            "sample_n":   len(lats),
            "p50_ms":     percentile(lats, 50),
            "p95_ms":     percentile(lats, 95),
            "mean_ms":    round(sum(lats) / len(lats), 1) if lats else 0,
            "max_ms":     max(lats) if lats else 0,
            "statuses":   hop_statuses.get(name, {}),
        })

    return {
        "pipeline_version": "2.0.0",
        "ring_buffer_size": _HOP_RING_SIZE,
        "requests_sampled": len(snapshot),
        "hops": hop_stats,
    }


# ── V1 Chat Trace Endpoint (Visual Pipeline) ─────────────

@app.post("/v1/chat/trace")
async def chat_trace(request: ChatRequest, claims: dict = Depends(verify_jwt)):
    """Detailed per-layer trace for visual pipeline display."""
    layers = []
    risk_running = 0.0
    pipeline_start = time.perf_counter()

    ctx = RequestContext(
        request_id=str(uuid.uuid4()),
        user_id=claims["user_id"],
        role=claims["role"],
        raw_prompt=request.prompt,
        clean_prompt=request.prompt,
    )

    def hop_ms(t0: float) -> int:
        return max(1, int((time.perf_counter() - t0) * 1000))

    mode = "auto" if request.model == "auto" else "explicit"
    opa_model = STANDARD_MODEL if mode == "auto" else request.model

    # Layer 1: JWT Auth (already passed via Depends)
    layers.append({"layer": 1, "name": "JWT Authentication", "status": "pass",
        "detail": f"Verified · user={ctx.user_id} · role={ctx.role}",
        "latency_ms": 0, "risk_score": 0.0, "findings": []})

    # Layer 2: Rate Limiting
    t = time.perf_counter()
    try:
        check_rate_limit(ctx.user_id, ctx.role)
        ctx.requests_last_minute = get_request_count(ctx.user_id)
        lms = hop_ms(t)
        ctx.record_hop("rate_limit", lms)
        layers.append({"layer": 2, "name": "Rate Limiting", "status": "pass",
            "detail": f"Request #{ctx.requests_last_minute} within window",
            "latency_ms": lms, "risk_score": 0.0, "findings": []})
    except HTTPException as e:
        layers.append({"layer": 2, "name": "Rate Limiting", "status": "block",
            "detail": str(e.detail), "latency_ms": hop_ms(t), "risk_score": 0.0, "findings": []})
        return {"request_id": ctx.request_id, "layers": layers, "final_decision": "block",
                "block_reason": str(e.detail), "risk_score": 0.0}

    # Layer 3: Input Sanitization
    t = time.perf_counter()
    original = ctx.clean_prompt
    ctx.clean_prompt = normalize_text(ctx.clean_prompt)
    changed = original != ctx.clean_prompt
    lms = hop_ms(t)
    ctx.record_hop("sanitize", lms)
    layers.append({"layer": 3, "name": "Input Sanitization", "status": "pass",
        "detail": f"NFKC + homoglyph · {'modified' if changed else 'no change'}",
        "latency_ms": lms, "risk_score": 0.0, "findings": [],
        "extra": {"modified": changed, "clean_prompt": ctx.clean_prompt[:100]}})

    # Layer 4: PII Scan
    t = time.perf_counter()
    findings_before = len(ctx.findings)
    ctx = await scan_pii(ctx)
    pii_findings = [{"type": f.description, "severity": f.severity, "score_delta": f.score_delta}
                    for f in ctx.findings[findings_before:]]
    pii_risk = sum(f["score_delta"] for f in pii_findings)
    risk_running += pii_risk
    lms = hop_ms(t)
    ctx.record_hop("pii_scan", lms)
    layers.append({"layer": 4, "name": "PII Scan (Presidio + Regex)", "status": "flag" if pii_findings else "pass",
        "detail": f"{'Detected: ' + ', '.join(f['type'] for f in pii_findings) if pii_findings else 'No PII detected'}",
        "latency_ms": lms, "risk_score": round(risk_running, 2), "findings": pii_findings})

    # Layer 5: Injection Scan
    t = time.perf_counter()
    findings_before = len(ctx.findings)
    ctx = scan_injection(ctx)
    inj_findings = [{"type": f.description, "severity": f.severity, "matched": f.matched, "score_delta": f.score_delta}
                    for f in ctx.findings[findings_before:]]
    inj_risk = sum(f["score_delta"] for f in inj_findings)
    risk_running += inj_risk
    lms = hop_ms(t)
    ctx.record_hop("injection_scan", lms)
    layers.append({"layer": 5, "name": "Injection Detection", "status": "flag" if inj_findings else "pass",
        "detail": f"{len(inj_findings)} pattern(s) matched" if inj_findings else "No injection patterns detected",
        "latency_ms": lms, "risk_score": round(risk_running, 2), "findings": inj_findings})

    # Layer 6: Risk Aggregation
    t = time.perf_counter()
    ctx = compute_risk_score(ctx)
    level = get_risk_level(ctx.risk_score)
    lms = hop_ms(t)
    ctx.record_hop("risk_score", lms)
    layers.append({"layer": 6, "name": "Risk Score Aggregation", "status": "flag" if ctx.risk_score > 0.3 else "pass",
        "detail": f"Score: {ctx.risk_score:.2f} ({level}) · capped aggregation",
        "latency_ms": lms, "risk_score": round(ctx.risk_score, 2), "findings": []})

    # Layer 7: Classifier
    if mode == "auto":
        clf = await classify_llm(ctx.clean_prompt)
    else:
        clf = classify(ctx.clean_prompt)
    ctx.complexity_tier = clf.complexity_tier
    ctx.intent_class    = clf.intent_class
    clf_cost = None
    if clf.input_tokens or clf.output_tokens:
        clf_cost = estimate_cost(clf.model, "", "",
                                 prompt_tokens=clf.input_tokens,
                                 completion_tokens=clf.output_tokens)
        ctx.input_tokens       += clf_cost.input_tokens
        ctx.output_tokens      += clf_cost.output_tokens
        ctx.estimated_cost_usd += clf_cost.total_cost_usd
    ctx.record_hop("classifier", clf.latency_ms, model=clf.model,
                   input_tokens=clf.input_tokens, output_tokens=clf.output_tokens,
                   estimated_cost_usd=(clf_cost.total_cost_usd if clf_cost else 0.0))
    layers.append({"layer": 7, "name": "Intent/Complexity Classifier", "status": "pass",
        "detail": f"mode={mode} · model={clf.model} · complexity={clf.complexity_tier} · intent={clf.intent_class} · words={clf.word_count} · conf={clf.confidence}",
        "latency_ms": clf.latency_ms, "risk_score": round(ctx.risk_score, 2), "findings": [],
        "extra": {"complexity_tier": clf.complexity_tier, "intent_class": clf.intent_class,
                  "word_count": clf.word_count, "confidence": clf.confidence,
                  "classifier_model": clf.model,
                  "input_tokens": clf.input_tokens, "output_tokens": clf.output_tokens}})

    # Layer 8: OPA Policy
    t = time.perf_counter()
    decision = await query_opa(ctx, opa_model)
    lms = hop_ms(t)
    ctx.record_hop("opa_policy", lms)
    if not decision["allow"]:
        layers.append({"layer": 8, "name": "OPA Policy Engine", "status": "block",
            "detail": f"DENIED: {decision['reason']}",
            "latency_ms": lms, "risk_score": round(ctx.risk_score, 2), "findings": []})
        return {"request_id": ctx.request_id, "layers": layers, "final_decision": "block",
                "block_reason": decision["reason"], "risk_score": round(ctx.risk_score, 2),
                "role": ctx.role, "user_id": ctx.user_id}
    layers.append({"layer": 8, "name": "OPA Policy Engine", "status": "pass",
        "detail": f"ALLOWED: {decision['reason']} · model_route={decision['model_route']}",
        "latency_ms": lms, "risk_score": round(ctx.risk_score, 2), "findings": []})

    # Layer 9: Model Routing
    t = time.perf_counter()
    routing = resolve_model(ctx.role, ctx.risk_score, decision["model_route"],
                            ctx.complexity_tier, ctx.intent_class,
                            mode=mode, requested_model=request.model)
    lms = hop_ms(t)
    ctx.record_hop("model_routing", lms)
    layers.append({"layer": 9, "name": "Model Routing", "status": "pass",
        "detail": f"tier={routing.tier} · model={routing.model} · {routing.reason}",
        "latency_ms": lms, "risk_score": round(ctx.risk_score, 2), "findings": []})

    # Layer 10: LLM Backend
    raw_response, llm_ms, gen_pt, gen_ct = await call_ollama(ctx.clean_prompt, routing.model)
    gen_cost = estimate_cost(routing.model, ctx.clean_prompt, raw_response,
                             prompt_tokens=gen_pt, completion_tokens=gen_ct)
    ctx.input_tokens       += gen_cost.input_tokens
    ctx.output_tokens      += gen_cost.output_tokens
    ctx.estimated_cost_usd += gen_cost.total_cost_usd
    ctx.record_hop("llm_backend", llm_ms, model=routing.model,
                   input_tokens=gen_cost.input_tokens, output_tokens=gen_cost.output_tokens,
                   estimated_cost_usd=gen_cost.total_cost_usd)
    layers.append({"layer": 10, "name": "LLM Backend (Ollama)", "status": "pass",
        "detail": f"model={routing.model} · {llm_ms}ms · in={gen_cost.input_tokens}tok · out={gen_cost.output_tokens}tok · cost=${gen_cost.total_cost_usd:.6f}",
        "latency_ms": llm_ms, "risk_score": round(ctx.risk_score, 2), "findings": [],
        "extra": {"input_tokens": gen_cost.input_tokens, "output_tokens": gen_cost.output_tokens,
                  "estimated_cost_usd": round(gen_cost.total_cost_usd, 8)}})

    # Layer 11: Output Scan
    t = time.perf_counter()
    clean_response, output_blocked, out_findings_list = scan_output(ctx, raw_response)
    out_findings = [{"type": f.description, "severity": f.severity} for f in out_findings_list]
    lms = hop_ms(t)
    ctx.record_hop("output_scan", lms)
    layers.append({"layer": 11, "name": "Output Scan", "status": "block" if output_blocked else "pass",
        "detail": "SECRETS DETECTED — response blocked" if output_blocked else "Response clean",
        "latency_ms": lms, "risk_score": round(ctx.risk_score, 2), "findings": out_findings})

    total_ms = max(1, int((time.perf_counter() - pipeline_start) * 1000))

    return {
        "request_id":        ctx.request_id,
        "layers":            layers,
        "final_decision":    "block" if output_blocked else "allow",
        "response":          clean_response,
        "risk_score":        round(ctx.risk_score, 2),
        "model_used":        routing.model,
        "routing_mode":      mode,
        "complexity_tier":   ctx.complexity_tier,
        "intent_class":      ctx.intent_class,
        "role":              ctx.role,
        "user_id":           ctx.user_id,
        "total_latency_ms":  total_ms,
        "input_tokens":      ctx.input_tokens,
        "output_tokens":     ctx.output_tokens,
        "estimated_cost_usd": round(ctx.estimated_cost_usd, 8),
    }
