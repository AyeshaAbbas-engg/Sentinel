import httpx
from fastapi import HTTPException
from context import RequestContext
from config import OPA_URL, OPA_TIMEOUT

OPA_POLICY_PATH = "/v1/data/sentinel/authz"


async def query_opa(ctx: RequestContext, requested_model: str) -> dict:
    """Sends request context to OPA. Fails closed on error."""
    input_doc = {
        "input": {
            "user": {
                "id": ctx.user_id,
                "role": ctx.role,
                "requests_last_minute": ctx.requests_last_minute,
            },
            "request": {
                "risk_score": round(ctx.risk_score, 2),
                "pii_detected": any(f.scanner == "pii" for f in ctx.findings),
                "injection_detected": any(f.scanner == "injection" for f in ctx.findings),
                "prompt": ctx.clean_prompt,
                "prompt_length": len(ctx.raw_prompt),
                "requested_model": requested_model,
            }
        }
    }

    try:
        async with httpx.AsyncClient(timeout=float(OPA_TIMEOUT)) as client:
            response = await client.post(f"{OPA_URL}{OPA_POLICY_PATH}", json=input_doc)
            response.raise_for_status()
            result = response.json()

        decision = result.get("result", {})
        allow = decision.get("allow", False)
        reason = decision.get("reason", "no reason returned")
        model_route = decision.get("model_route", "phi3:mini")

        if not allow:
            model_route = "BLOCKED"

        return {"allow": allow, "reason": reason, "model_route": model_route}

    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="OPA unreachable — failing closed")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=503, detail=f"OPA returned error: {e.response.status_code}")
    except Exception:
        raise HTTPException(status_code=503, detail="OPA error — failing closed")
