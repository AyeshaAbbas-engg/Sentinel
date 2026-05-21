# ════════════════════════════════════════════════════════
# SENTINEL — Model Router
# Translates OPA's model_route decision into the actual
# Ollama model string. Single source of truth for model
# selection. All tiers resolve to phi3:mini (local setup).
# ════════════════════════════════════════════════════════

from dataclasses import dataclass

# ── Available models on this node ───────────────────────
AVAILABLE_MODELS = {
    "phi3:mini": "phi3:mini",
}

# ── Routing tier labels (for logging/audit) ──────────────
ROUTING_TIERS = {
    "admin_low_risk":     "Full access — admin, risk < 0.3",
    "admin_medium_risk":  "Standard access — admin, risk 0.3–0.7",
    "analyst_low_risk":   "Standard access — analyst, risk < 0.3",
    "analyst_medium_risk":"Degraded access — analyst, risk 0.3–0.6",
    "guest_any":          "Restricted access — guest",
    "blocked":            "BLOCKED — risk > 0.7",
}


@dataclass
class RoutingDecision:
    model: str          # actual ollama model string
    tier: str           # tier label for audit log
    reason: str         # human-readable routing reason


def resolve_model(role: str, risk_score: float, opa_model_route: str) -> RoutingDecision:
    """
    Takes OPA's model_route + request context and returns
    a RoutingDecision with the final model and tier label.

    OPA is the authority — this function validates and enriches
    OPA's decision rather than making its own.
    """

    # ── Blocked by OPA ───────────────────────────────────
    if opa_model_route == "BLOCKED":
        return RoutingDecision(
            model="BLOCKED",
            tier="blocked",
            reason=f"Request blocked by policy — risk score {risk_score:.2f}"
        )

    # ── Validate OPA returned a known model ──────────────
    resolved = AVAILABLE_MODELS.get(opa_model_route, "phi3:mini")

    # ── Determine tier for audit ─────────────────────────
    if role == "admin" and risk_score < 0.3:
        tier = "admin_low_risk"
        reason = f"Admin role, low risk ({risk_score:.2f}) — full access tier"

    elif role == "admin" and risk_score <= 0.7:
        tier = "admin_medium_risk"
        reason = f"Admin role, medium risk ({risk_score:.2f}) — standard access tier"

    elif role == "analyst" and risk_score < 0.3:
        tier = "analyst_low_risk"
        reason = f"Analyst role, low risk ({risk_score:.2f}) — standard access tier"

    elif role == "analyst" and risk_score < 0.6:
        tier = "analyst_medium_risk"
        reason = f"Analyst role, medium risk ({risk_score:.2f}) — degraded access tier"

    elif role == "guest":
        tier = "guest_any"
        reason = f"Guest role — restricted access tier"

    else:
        tier = "analyst_low_risk"
        reason = f"Default tier — role={role}, risk={risk_score:.2f}"

    return RoutingDecision(model=resolved, tier=tier, reason=reason)


def get_routing_summary(decision: RoutingDecision) -> dict:
    """Returns a dict suitable for logging."""
    return {
        "model_selected": decision.model,
        "routing_tier": decision.tier,
        "routing_reason": decision.reason,
    }