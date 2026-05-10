import uuid
import time
import httpx
from fastapi import FastAPI,Depends,Request
from middleware.auth import verify_jwt
from middleware.rate_limit import check_rate_limit
from observability.logger import log_request
from pydantic import BaseModel
from context import RequestContext

app=FastAPI(title="Sentinel Gateway",version="0.1.0")

class ChatRequest(BaseModel):
    prompt:str
    model:str="phi3:mini"

class ChatResponse(BaseModel):
    request_id:str
    response:str
    model_used:str
    risk_score:float
    user_id:str
    role:str

@app.post("/chat",response_model=ChatResponse)
async def chat(request:ChatRequest, claims:dict=Depends(verify_jwt)):
    start_time=time.time()
    ctx=RequestContext(
        request_id=str(uuid.uuid4()),
        user_id=claims["user_id"],
        role=claims["role"],
        raw_prompt=request.prompt,
        clean_prompt=request.prompt.strip()
    )
    check_rate_limit(ctx.user_id, ctx.role)
    ollama_response=await call_ollama(ctx.clean_prompt,request.model)

    ctx.model_used=request.model
    ctx.latency_ms=int((time.time()-start_time)*1000)
    ctx.policy_decision="allow"
    log_request(ctx)
    return ChatResponse(
        request_id=ctx.request_id,
        response=ollama_response,
        model_used=ctx.model_used,
        risk_score=ctx.risk_score,
        user_id=ctx.user_id,
        role=ctx.role,
    )

@app.get("/health")
async def health():
    return {"status":"ok","service":"sentinel-gateway"}

async def call_ollama(prompt:str,model:str)->str:
    async with httpx.AsyncClient(timeout=120.0) as client:
        response=await client.post(
            "http://ollama:11434/api/generate",
            json={
                "model":model,
                "prompt":prompt,
                "stream":False
            }
        )
        data=response.json()
        return data.get("response","No response from Model :(")