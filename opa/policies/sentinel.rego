package sentinel.authz

import rego.v1

# ════════════════════════════════════════════════════════
# SENTINEL — Authorization & Model-Routing Policy  (v2)
#
# New in v2 (classifier-aware):
#   • input.request.complexity_tier  — "simple" | "moderate" |
#                                      "complex" | "unknown"
#   • input.request.intent_class     — "qa" | "code" | "analysis" |
#                                      "creative" | "other" | "unknown"
#
# These fields are populated by the classifier hop (Stage 7) that
# runs BEFORE OPA is queried (Stage 8).  They are safe to use in
# deny rules and in model_route rules; when the classifier has not
# yet run they default to "unknown".
#
# Per-hop governance addition (Rule 6):
#   Guests are denied complex + code requests regardless of the
#   risk score.  This is the first policy rule that acts on the
#   classifier's output, making OPA genuinely per-hop-aware.
# ════════════════════════════════════════════════════════

# ── Defaults ─────────────────────────────────────────────
default allow       := false
default model_route := "phi3:mini"

# ── Allow ─────────────────────────────────────────────────
allow if {
    count(deny_reasons) == 0
}

# ── Reason string ─────────────────────────────────────────
reason := concat("; ", deny_reasons) if {
    count(deny_reasons) > 0
} else := "all checks passed"

# ════════════════════════════════════════════════════════
# DENY RULES  (partial set — all matching rules fire)
# ════════════════════════════════════════════════════════

# Rule 1 — Risk hard block
deny_reasons contains sprintf("risk score %.2f exceeds threshold 0.7", [input.request.risk_score]) if {
    input.request.risk_score > 0.7
}

# Rule 2 — PII detected, non-admin role
deny_reasons contains "PII detected — only admins may send PII prompts" if {
    input.request.pii_detected == true
    input.user.role != "admin"
}

# Rule 3 — Guest model lock
# In auto mode the gateway presents STANDARD_MODEL to OPA, so this rule
# only fires when a guest explicitly requests a non-standard model string.
deny_reasons contains "guests are restricted to phi3:mini only" if {
    input.user.role == "guest"
    input.request.requested_model != "phi3:mini"
}

# Rule 4 — Analyst rate cap
deny_reasons contains "rate limit exceeded for analyst role" if {
    input.user.role == "analyst"
    input.user.requests_last_minute > 20
}

# Rule 5 — Analyst code-execution gate
deny_reasons contains "code execution not permitted for analyst role" if {
    input.user.role == "analyst"
    some keyword in analyst_code_keywords
    contains(lower(input.request.prompt), keyword)
}

# Rule 6 — Per-hop governance: guests may not run complex code requests
# This rule consumes the classifier's complexity_tier and intent_class
# directly, making OPA aware of the classifier hop's output.
# Rationale: a complex code prompt routed to a guest implies a heavy
# generation hop (phi3:mini + long output) that is disproportionate
# to the guest tier — block it early before the LLM is invoked.
deny_reasons contains "guests may not submit complex code requests" if {
    input.user.role == "guest"
    input.request.complexity_tier == "complex"
    input.request.intent_class    == "code"
}

# ════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════

denied if {
    count(deny_reasons) > 0
}

analyst_code_keywords := ["execute", "run code", "bash", "subprocess", "shell", "os.system"]

# ════════════════════════════════════════════════════════
# MODEL ROUTING  (v2: complexity-aware)
#
# Priority (highest → lowest):
#   1. Request blocked             → no route (deny_reasons fires first)
#   2. Guest role                  → standard model (pin)
#   3. Complex intent              → standard model (more capable)
#   4. simple/moderate + low risk  → cheap model  (cost optimisation)
#   5. Default                     → standard model (safe fallback)
#
# The gateway router (policy/router.py) uses these values only as a
# floor / authority check.  In auto mode it also consults
# COMPLEXITY_MODEL_MAP, so OPA returning "phi3:mini" for a complex
# request and "qwen2.5:1.5b" for a simple one is the canonical signal.
# ════════════════════════════════════════════════════════

# Guest — always pinned to standard model
model_route := "phi3:mini" if {
    input.user.role == "guest"
}

# Complex requests — standard model regardless of role
model_route := "phi3:mini" if {
    input.user.role != "guest"
    input.request.complexity_tier == "complex"
}

# Simple prompt, low risk, non-guest, non-code — route to cheap model
# Code intent is excluded here; the code-intent rule below takes priority.
model_route := "qwen2.5:1.5b" if {
    input.user.role != "guest"
    input.request.complexity_tier == "simple"
    input.request.risk_score      <= 0.3
    input.request.intent_class    != "code"
}

# Moderate prompt, low risk, non-guest, non-code — route to cheap model
model_route := "qwen2.5:1.5b" if {
    input.user.role != "guest"
    input.request.complexity_tier == "moderate"
    input.request.risk_score      <= 0.3
    input.request.intent_class    != "code"
}

# Simple/moderate but elevated risk — standard model (more scrutiny)
model_route := "phi3:mini" if {
    input.user.role != "guest"
    input.request.complexity_tier in {"simple", "moderate"}
    input.request.risk_score > 0.3
}

# Code intent, any complexity, non-guest — always standard model
# (code generation benefits from the more capable model)
model_route := "phi3:mini" if {
    input.user.role != "guest"
    input.request.intent_class == "code"
}

# Admin low-risk — standard model (unchanged from v1 for back-compat)
model_route := "phi3:mini" if {
    input.user.role    == "admin"
    input.request.risk_score < 0.3
    input.request.complexity_tier == "unknown"
}

# Analyst within limits — standard model (back-compat for unknown tier)
model_route := "phi3:mini" if {
    input.user.role    == "analyst"
    input.request.risk_score <= 0.7
    input.request.complexity_tier == "unknown"
}
