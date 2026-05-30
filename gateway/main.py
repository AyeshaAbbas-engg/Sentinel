import uuid
import time
import httpx
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException, Response
from pydantic import BaseModel, field_validator
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from datetime import datetime, timedelta, timezone

from config import (
    JWT_SECRET, JWT_ALGORITHM, ALLOWED_ORIGINS, MAX_PROMPT_LENGTH,
    OLLAMA_URL, PRESIDIO_URL, OPA_URL,
)
from context import RequestContext
from middleware.auth import verify_jwt
from middleware.rate_limit import check_rate_limit, get_request_count
from observability.logger import log_request
from observability.metrics import (
    record_request, record_block, record_pii,
    record_injection, record_model, record_output_flag
)
from scanning.pii import scan_pii
from scanning.injection import scan_injection
from scanning.sanitize import normalize_text
from scanning.risk import compute_risk_score, get_risk_level
from scanning.output import scan_output
from policy.opa_client import query_opa
from policy.router import resolve_model, get_routing_summary
from backends.ollama import call_ollama

app = FastAPI(title="SENTINEL Gateway", version="1.1.0")

# ── CORS — locked down ───────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Request/Response Models ──────────────────────────────

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


# ── Metrics Endpoint ─────────────────────────────────────

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── Health Check — deep (verifies downstream) ────────────

@app.get("/health")
async def health():
    checks = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, url in [("presidio", f"{PRESIDIO_URL}/health"), ("opa", f"{OPA_URL}/health"), ("ollama", f"{OLLAMA_URL}")]:
            try:
                r = await client.get(url)
                checks[name] = "ok" if r.status_code < 400 else "degraded"
            except Exception:
                checks[name] = "unreachable"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {
        "status": overall,
        "service": "sentinel-gateway",
        "version": "1.1.0",
        "dependencies": checks,
        "pipeline": [
            "jwt_auth", "rate_limit", "sanitize", "pii_scan",
            "injection_scan", "risk_score",
            "opa_policy", "model_routing",
            "llm_backend", "output_scan"
        ]
    }


# ── Token Endpoint (demo) ────────────────────────────────

class TokenRequest(BaseModel):
    user_id: str
    role: str

class TokenResponse(BaseModel):
    access_token: str
    role: str
    user_id: str
    expires_in: int
    issued_at: str

@app.post("/token", response_model=TokenResponse)
async def generate_token(req: TokenRequest):
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


# ── V1 Chat Endpoint ────────────────────────────────────

@app.post("/v1/chat", response_model=ChatResponse)
@app.post("/chat", response_model=ChatResponse, include_in_schema=False)
async def chat(request: ChatRequest, claims: dict = Depends(verify_jwt)):
    start_time = time.time()

    # ── Build Request Context ────────────────────────────
    ctx = RequestContext(
        request_id=str(uuid.uuid4()),
        user_id=claims["user_id"],
        role=claims["role"],
        raw_prompt=request.prompt,
        clean_prompt=request.prompt,
    )

    # ── Layer 1: Rate Limiting ───────────────────────────
    check_rate_limit(ctx.user_id, ctx.role)
    ctx.requests_last_minute = get_request_count(ctx.user_id)

    # ── Layer 2: Input Sanitization ──────────────────────
    ctx.clean_prompt = normalize_text(ctx.clean_prompt)

    # ── Layer 3: PII Scan ────────────────────────────────
    ctx = await scan_pii(ctx)

    # ── Layer 4: Injection Scan ──────────────────────────
    ctx = scan_injection(ctx)

    # ── Layer 5: Risk Aggregation ────────────────────────
    ctx = compute_risk_score(ctx)

    # ── Layer 6: OPA Policy Decision ─────────────────────
    decision = await query_opa(ctx, request.model)

    if not decision["allow"]:
        ctx.policy_decision = "block"
        ctx.policy_reason = decision["reason"]
        ctx.latency_ms = int((time.time() - start_time) * 1000)
        record_request(ctx.role, "block", ctx.risk_score, ctx.latency_ms)
        record_block(decision["reason"])
        log_request(ctx)
        raise HTTPException(status_code=403, detail={
    "reason": decision["reason"],
    "risk_score": round(ctx.risk_score, 2),
    "injection_detected": any(f.scanner == "injection" for f in ctx.findings),
    "pii_detected": any(f.scanner == "pii" for f in ctx.findings),
})

    # ── Layer 7: Model Routing ───────────────────────────
    routing = resolve_model(ctx.role, ctx.risk_score, decision["model_route"])

    # ── Layer 8: LLM Backend ─────────────────────────────
    raw_response = await call_ollama(ctx.clean_prompt, routing.model)

    # ── Layer 9: Output Scan ─────────────────────────────
    clean_response, output_blocked, output_findings = scan_output(ctx, raw_response)

    # ── Finalize Context ─────────────────────────────────
    ctx.model_used = routing.model
    ctx.latency_ms = int((time.time() - start_time) * 1000)
    ctx.policy_decision = "allow"
    ctx.policy_reason = decision["reason"]

    # ── Metrics ──────────────────────────────────────────
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

    # ── Audit Log ────────────────────────────────────────
    log_request(ctx)

    # ── Response ─────────────────────────────────────────
    pii_entities = [f.description for f in ctx.findings if f.scanner == "pii"]

    return ChatResponse(
        request_id=ctx.request_id,
        response=clean_response,
        model_used=ctx.model_used,
        routing_tier=routing.tier,
        routing_reason=routing.reason,
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
    )
