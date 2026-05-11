import uuid
import time
import httpx

from fastapi import FastAPI, Depends
from pydantic import BaseModel

from context import RequestContext
from middleware.auth import verify_jwt
from middleware.rate_limit import check_rate_limit
from observability.logger import log_request
from scanning.pii import scan_pii
from scanning.injection import scan_injection

app = FastAPI(title="SENTINEL Gateway", version="0.1.0")

class ChatRequest(BaseModel):
    prompt: str
    model: str = "phi3:mini"

class ChatResponse(BaseModel):
    request_id: str
    response: str
    model_used: str
    risk_score: float
    user_id: str
    role: str
    pii_detected: bool
    pii_entities: list
    injection_detected: bool

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, claims: dict = Depends(verify_jwt)):

    start_time = time.time()

    ctx = RequestContext(
        request_id=str(uuid.uuid4()),
        user_id=claims["user_id"],
        role=claims["role"],
        raw_prompt=request.prompt,
        clean_prompt=request.prompt,
    )

    # Layer 2 — Rate limit
    check_rate_limit(ctx.user_id, ctx.role)

    # Layer 3a — PII scan
    ctx = await scan_pii(ctx)

    # Layer 3b — Injection scan
    ctx = scan_injection(ctx)

    # Check if injection was detected
    injection_findings = [f for f in ctx.findings if f.scanner == "injection"]
    injection_detected = len(injection_findings) > 0

    # Block if risk score is critical
    if ctx.risk_score >= 0.8:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail=f"Request blocked. Risk score {ctx.risk_score:.2f} exceeds threshold."
        )

    # Forward clean prompt to Ollama
    ollama_response = await call_ollama(ctx.clean_prompt, request.model)

    ctx.model_used = request.model
    ctx.latency_ms = int((time.time() - start_time) * 1000)
    ctx.policy_decision = "allow"

    pii_entities = [f.description for f in ctx.findings if f.scanner == "pii"]

    log_request(ctx)

    return ChatResponse(
        request_id=ctx.request_id,
        response=ollama_response,
        model_used=ctx.model_used,
        risk_score=ctx.risk_score,
        user_id=ctx.user_id,
        role=ctx.role,
        pii_detected=len(pii_entities) > 0,
        pii_entities=pii_entities,
        injection_detected=injection_detected,
    )

@app.get("/health")
async def health():
    return {"status": "ok", "service": "sentinel-gateway"}

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