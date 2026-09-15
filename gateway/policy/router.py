# ════════════════════════════════════════════════════════
# SENTINEL — Model Router  (v2: multi-model + classifier-aware)
#
# Translates OPA's model_route decision + classifier output
# into a final Ollama model string and audit-ready tier label.
#
# The single-node deployment uses a small cheap tier and a standard tier.
# Extending it with another local model requires only an AVAILABLE_MODELS entry
# and an intentional update to the tier map below.
# ════════════════════════════════════════════════════════

from dataclasses import dataclass

# ── Available models on this node ───────────────────────
# Add entries here as new models are pulled via `ollama pull`.
# Key = logical name used in OPA policy / env config.
# Value = exact string passed to the Ollama API.
AVAILABLE_MODELS: dict[str, str] = {
    "phi3:mini":    "phi3:mini",
    "qwen2.5:1.5b": "qwen2.5:1.5b",   # cheap tier for simple/moderate prompts
}

# Fallback when a requested model is not locally available
DEFAULT_MODEL = "phi3:mini"

# ── Complexity → preferred model mapping ─────────────────
# The cost/quality trade-off made concrete: cheap small model for
# simple/moderate prompts, larger model for complex reasoning. Only
# consulted in "auto" mode (classifier-driven routing).
COMPLEXITY_MODEL_MAP: dict[str, str] = {
    "simple":   "qwen2.5:1.5b",
    "moderate": "qwen2.5:1.5b",
    "complex":  "phi3:mini",
}

# ── Routing tier labels (for logging/audit) ──────────────
ROUTING_TIERS: dict[str, str] = {
    "admin_low_risk":       "Full access — admin, risk < 0.3",
    "admin_medium_risk":    "Standard access — admin, risk 0.3–0.7",
    "analyst_low_risk":     "Standard access — analyst, risk < 0.3",
    "analyst_medium_risk":  "Degraded access — analyst, risk 0.3–0.6",
    "guest_any":            "Restricted access — guest",
    "blocked":              "BLOCKED — risk > 0.7",
}


@dataclass
class RoutingDecision:
    model: str              # actual Ollama model string
    tier: str               # tier label for audit log
    reason: str             # human-readable routing reason
    complexity_tier: str    # classifier output (simple|moderate|complex)
    intent_class: str       # classifier output (qa|code|analysis|creative|other)


def resolve_model(
    role: str,
    risk_score: float,
    opa_model_route: str,
    complexity_tier: str = "unknown",
    intent_class: str = "unknown",
    mode: str = "explicit",
    requested_model: str = DEFAULT_MODEL,
) -> RoutingDecision:
    """
    Takes OPA's model_route + request context + classifier output and
    returns a RoutingDecision with the final model and tier label.

    OPA is the authority on *whether* to route (allow/deny) and pins
    guests. Among the allowed set the model is chosen by:
      - guest              → DEFAULT_MODEL (policy pin)
      - OPA named a non-default model → use it directly
      - elevated risk       → standard model (the OPA default is otherwise
                             ambiguous, so preserve the conservative route)
      - mode == "auto"     → COMPLEXITY_MODEL_MAP[complexity_tier]
                             (classifier-driven cost/quality routing)
      - mode == "explicit" → the caller's requested_model (if available)
    """

    # ── Blocked by OPA ───────────────────────────────────
    if opa_model_route == "BLOCKED":
        return RoutingDecision(
            model="BLOCKED",
            tier="blocked",
            reason=f"Request blocked by policy — risk score {risk_score:.2f}",
            complexity_tier=complexity_tier,
            intent_class=intent_class,
        )

    # ── Model selection ──────────────────────────────────
    # Authority order (highest → lowest):
    #   1. Guest pin            — always DEFAULT_MODEL, every mode
    #   2. Explicit mode        — honor requested_model (back-compat guarantee)
    #   3. Auto mode / OPA wins — OPA's model_route is the canonical signal;
    #                             it already encodes complexity+risk+intent from
    #                             the Rego rules, so trust it directly.
    #                             COMPLEXITY_MODEL_MAP is a fallback for the case
    #                             where OPA returned the floor default.
    if role == "guest":
        # Policy: guests are pinned to the standard model in every mode.
        resolved = DEFAULT_MODEL

    elif mode == "explicit":
        # Back-compat: caller chose a model explicitly → honor it.
        # OPA's model_route is NOT consulted here — it was built from the
        # classifier tier, not the caller's intent, so it must not override.
        resolved = AVAILABLE_MODELS.get(requested_model, DEFAULT_MODEL)

    else:
        # Auto mode: OPA is authoritative.
        # If OPA returned a real named model, use it directly.
        # Only fall back to COMPLEXITY_MODEL_MAP when OPA returned the
        # floor default (phi3:mini), which happens for unknown tiers or
        # back-compat unknown-tier rules — in that case the map owns it.
        if opa_model_route in AVAILABLE_MODELS and opa_model_route != DEFAULT_MODEL:
            resolved = AVAILABLE_MODELS[opa_model_route]
        elif risk_score > 0.3:
            # Rego intentionally returns the standard model for elevated-risk
            # requests.  As it is also the policy default, preserve that
            # conservative decision here rather than treating it as an
            # unspecified route and falling back to the cheap model.
            resolved = DEFAULT_MODEL
        else:
            preferred = COMPLEXITY_MODEL_MAP.get(complexity_tier, DEFAULT_MODEL)
            resolved = AVAILABLE_MODELS.get(preferred, DEFAULT_MODEL)

    # ── Tier label for audit ─────────────────────────────
    if role == "admin" and risk_score < 0.3:
        tier = "admin_low_risk"
        reason = (f"Admin role, low risk ({risk_score:.2f}) — full access tier"
                  f" | {complexity_tier} complexity → {resolved}")

    elif role == "admin" and risk_score <= 0.7:
        tier = "admin_medium_risk"
        reason = (f"Admin role, medium risk ({risk_score:.2f}) — standard access tier"
                  f" | {complexity_tier} complexity → {resolved}")

    elif role == "analyst" and risk_score < 0.3:
        tier = "analyst_low_risk"
        reason = (f"Analyst role, low risk ({risk_score:.2f}) — standard access tier"
                  f" | {complexity_tier} complexity → {resolved}")

    elif role == "analyst" and risk_score < 0.6:
        tier = "analyst_medium_risk"
        reason = (f"Analyst role, medium risk ({risk_score:.2f}) — degraded access tier"
                  f" | {complexity_tier} complexity → {resolved}")

    elif role == "guest":
        tier = "guest_any"
        reason = f"Guest role — restricted access tier | {complexity_tier} complexity → {resolved}"

    else:
        tier = "analyst_low_risk"
        reason = (f"Default tier — role={role}, risk={risk_score:.2f}"
                  f" | {complexity_tier} complexity → {resolved}")

    return RoutingDecision(
        model=resolved,
        tier=tier,
        reason=reason,
        complexity_tier=complexity_tier,
        intent_class=intent_class,
    )
