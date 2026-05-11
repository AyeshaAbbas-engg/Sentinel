import uuid
import time
import httpx

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

from context import RequestContext
from middleware.auth import verify_jwt
from middleware.rate_limit import check_rate_limit
from observability.logger import log_request
from scanning.pii import scan_pii
from scanning.injection import scan_injection
from scanning.risk import compute_risk_score, should_block, get_risk_level
from scanning.output import scan_output

app = FastAPI(title="SENTINEL Gateway", version="1.0.0")

# ── Request/Response Models ──────────────────────────────

class ChatRequest(BaseModel):
    prompt: str
    model: str = "phi3:mini"

class ChatResponse(BaseModel):
    request_id: str
    response: str
    model_used: str
    risk_score: float
    risk_level: str
    user_id: str
    role: str
    pii_detected: bool
    pii_entities: list
    injection_detected: bool
    output_flagged: bool
    policy_decision: str

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

    # ── Layer 2: Rate Limiting ───────────────────────────
    check_rate_limit(ctx.user_id, ctx.role)

    # ── Layer 3a: PII Scan ───────────────────────────────
    ctx = await scan_pii(ctx)

    # ── Layer 3b: Injection Scan ─────────────────────────
    ctx = scan_injection(ctx)

    # ── Layer 3c: Risk Aggregation ───────────────────────
    ctx = compute_risk_score(ctx)

    # ── Layer 3d: Policy Decision ────────────────────────
    block, reason = should_block(ctx.risk_score, ctx.role)
    if block:
        ctx.policy_decision = "block"
        ctx.policy_reason = reason
        ctx.latency_ms = int((time.time() - start_time) * 1000)
        log_request(ctx)
        raise HTTPException(status_code=403, detail=reason)

    # ── Layer 4: LLM Backend ─────────────────────────────
    raw_response = await call_ollama(ctx.clean_prompt, request.model)

    # ── Layer 5: Output Scan ─────────────────────────────
    clean_response, output_blocked, _ = scan_output(ctx, raw_response)

    # ── Finalize Context ─────────────────────────────────
    ctx.model_used = request.model
    ctx.latency_ms = int((time.time() - start_time) * 1000)
    ctx.policy_decision = "allow"
    ctx.policy_reason = "all checks passed"

    # ── Audit Log ────────────────────────────────────────
    log_request(ctx)

    # ── Response ─────────────────────────────────────────
    pii_entities = [f.description for f in ctx.findings if f.scanner == "pii"]
    injection_findings = [f for f in ctx.findings if f.scanner == "injection"]

    return ChatResponse(
        request_id=ctx.request_id,
        response=clean_response,
        model_used=ctx.model_used,
        risk_score=ctx.risk_score,
        risk_level=get_risk_level(ctx.risk_score),
        user_id=ctx.user_id,
        role=ctx.role,
        pii_detected=len(pii_entities) > 0,
        pii_entities=pii_entities,
        injection_detected=len(injection_findings) > 0,
        output_flagged=output_blocked,
        policy_decision=ctx.policy_decision,
    )

# ── Health Check ─────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentinel-gateway",
        "version": "1.0.0",
        "pipeline": [
            "jwt_auth",
            "rate_limit",
            "pii_scan",
            "injection_scan",
            "risk_score",
            "policy_engine",
            "llm_backend",
            "output_scan"
        ]
    }

# ── Ollama Client ─────────────────────────────────────────

async def call_ollama(prompt: str, model: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                "http://ollama:11434/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            data = response.json()
            return data.get("response", "No response from model")
    except httpx.ReadTimeout:
        return "Model timeout — please try again"
    except Exception as e:
        return f"Model error: {str(e)}"