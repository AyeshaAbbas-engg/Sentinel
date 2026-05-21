import os
import httpx
from context import RequestContext

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_POLICY_PATH = "/v1/data/sentinel/authz"


async def query_opa(ctx: RequestContext, requested_model: str) -> dict:
    """
    Sends request context to OPA and returns the policy decision.

    Returns dict with:
        - allow:       bool
        - reason:      str
        - model_route: str  (phi3:mini or BLOCKED)
    """

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
                "requested_model": requested_model,
            }
        }
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{OPA_URL}{OPA_POLICY_PATH}",
                json=input_doc
            )
            response.raise_for_status()
            result = response.json()

        decision = result.get("result", {})

        allow       = decision.get("allow", False)
        reason      = decision.get("reason", "no reason returned")
        model_route = decision.get("model_route", "phi3:mini")

        # Safety: if OPA says deny but model_route wasn't BLOCKED, force it
        if not allow:
            model_route = "BLOCKED"

        return {
            "allow":       allow,
            "reason":      reason,
            "model_route": model_route,
        }

    except httpx.ConnectError:
        # OPA unreachable — fail closed
        return {
            "allow":       False,
            "reason":      "OPA unreachable — failing closed",
            "model_route": "BLOCKED",
        }
    except Exception as e:
        return {
            "allow":       False,
            "reason":      f"OPA error: {str(e)}",
            "model_route": "BLOCKED",
        }