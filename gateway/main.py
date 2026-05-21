import uuid
import time
import httpx
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException, Response
from pydantic import BaseModel
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from datetime import datetime, timedelta, timezone
import os
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
from scanning.risk import compute_risk_score, get_risk_level
from scanning.output import scan_output
from policy.opa_client import query_opa
from policy.router import resolve_model, get_routing_summary

app = FastAPI(title="SENTINEL Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ── Request/Response Models ──────────────────────────────

class ChatRequest(BaseModel):
    prompt: str
    model: str = "phi3:mini"

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
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

# ── Health Check ─────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentinel-gateway",
        "version": "1.0.0",
        "pipeline": [
            "jwt_auth", "rate_limit", "pii_scan",
            "injection_scan", "risk_score",
            "opa_policy", "model_routing",
            "llm_backend", "output_scan"
        ]
    }


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
    """Demo token endpoint — generates JWT for UI testing."""
    if req.role not in ["admin", "analyst", "guest"]:
        raise HTTPException(status_code=400, detail="Role must be admin, analyst, or guest")

    JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-super-secret-key-2026")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=60)

    payload = {
        "sub": req.user_id,
        "role": req.role,
        "iat": now,
        "exp": exp,
    }

    from jose import jwt as jose_jwt
    token = jose_jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return TokenResponse(
        access_token=token,
        role=req.role,
        user_id=req.user_id,
        expires_in=3600,
        issued_at=now.isoformat()
    )
# ── Main Endpoint ────────────────────────────────────────

@app.post("/chat", response_model=ChatResponse)

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

    # ── Layer 2: PII Scan ────────────────────────────────
    ctx = await scan_pii(ctx)

    # ── Layer 3: Injection Scan ──────────────────────────
    ctx = scan_injection(ctx)

    # ── Layer 4: Risk Aggregation ────────────────────────
    ctx = compute_risk_score(ctx)

    # ── Layer 5: OPA Policy Decision ─────────────────────
    decision = await query_opa(ctx, request.model)

    if not decision["allow"]:
        ctx.policy_decision = "block"
        ctx.policy_reason = decision["reason"]
        ctx.latency_ms = int((time.time() - start_time) * 1000)

        # ── Metrics: blocked request ─────────────────────
        record_request(ctx.role, "block", ctx.risk_score, ctx.latency_ms)
        record_block(decision["reason"])

        log_request(ctx)
        raise HTTPException(status_code=403, detail=decision["reason"])

    # ── Layer 6: Model Routing ───────────────────────────
    routing = resolve_model(ctx.role, ctx.risk_score, decision["model_route"])

    # ── Layer 7: LLM Backend ─────────────────────────────
    raw_response = await call_ollama(ctx.clean_prompt, routing.model)

    # ── Layer 8: Output Scan ─────────────────────────────
    clean_response, output_blocked, output_findings = scan_output(ctx, raw_response)

    # ── Finalize Context ─────────────────────────────────
    ctx.model_used = routing.model
    ctx.latency_ms = int((time.time() - start_time) * 1000)
    ctx.policy_decision = "allow"
    ctx.policy_reason = decision["reason"]

    # ── Metrics: allowed request ─────────────────────────
    record_request(ctx.role, "allow", ctx.risk_score, ctx.latency_ms)
    record_model(routing.model)

    # PII metrics
    pii_findings = [f for f in ctx.findings if f.scanner == "pii"]
    if pii_findings:
        record_pii([f.description for f in pii_findings])

    # Injection metrics
    injection_findings = [f for f in ctx.findings if f.scanner == "injection"]
    if injection_findings:
        record_injection(injection_findings)

    # Output flag metrics
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

# ── Ollama Client ─────────────────────────────────────────

async def call_ollama(prompt: str, model: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                "http://ollama:11434/api/generate",
                json={"model": model, "prompt": prompt, "stream": False}
            )
            data = response.json()
            return data.get("response", "No response from model")
    except httpx.ReadTimeout:
        return "Model timeout — please try again"
    except Exception as e:
        return f"Model error: {str(e)}"