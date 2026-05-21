package sentinel.authz

import rego.v1

# ════════════════════════════════════════════════════════
# DEFAULTS — deny everything unless explicitly allowed
# ════════════════════════════════════════════════════════

default allow := false
default reason := "request did not match any allow rule"
default model_route := "phi3:mini"

# ════════════════════════════════════════════════════════
# ALLOW RULE — pass only if nothing denied
# ════════════════════════════════════════════════════════

allow if {
    not denied
}

reason := "all checks passed" if {
    not denied
}

# ════════════════════════════════════════════════════════
# POLICY 1 — Risk Score Hard Block
# Blocks ALL roles when risk_score > 0.7
# ════════════════════════════════════════════════════════

denied if {
    input.request.risk_score > 0.7
}

reason := sprintf("risk score %.2f exceeds threshold 0.7", [input.request.risk_score]) if {
    input.request.risk_score > 0.7
}

# ════════════════════════════════════════════════════════
# POLICY 2 — PII + Non-Admin Block
# Only admins may send prompts containing PII
# ════════════════════════════════════════════════════════

denied if {
    input.request.pii_detected == true
    input.user.role != "admin"
}

reason := "PII detected — only admins may send PII prompts" if {
    input.request.pii_detected == true
    input.user.role != "admin"
}

# ════════════════════════════════════════════════════════
# POLICY 3 — Guest Model Restriction
# Guests cannot request any model — always routed to phi3:mini
# Block if they explicitly request something else
# ════════════════════════════════════════════════════════

denied if {
    input.user.role == "guest"
    input.request.requested_model != "phi3:mini"
}

reason := "guests are restricted to phi3:mini only" if {
    input.user.role == "guest"
    input.request.requested_model != "phi3:mini"
}

# ════════════════════════════════════════════════════════
# POLICY 4 — Analyst Rate Limit Enforcement
# Second enforcement point after gateway rate limiter
# ════════════════════════════════════════════════════════

denied if {
    input.user.role == "analyst"
    input.user.requests_last_minute > 20
}

reason := "rate limit exceeded for analyst role" if {
    input.user.role == "analyst"
    input.user.requests_last_minute > 20
}

# ════════════════════════════════════════════════════════
# POLICY 5 — Analyst Code Execution Gate
# Analysts cannot request code generation or execution
# ════════════════════════════════════════════════════════

analyst_code_keywords := ["execute", "run code", "bash", "subprocess", "shell", "os.system"]

denied if {
    input.user.role == "analyst"
    some keyword in analyst_code_keywords
    contains(lower(input.request.prompt), keyword)
}

reason := "code execution not permitted for analyst role" if {
    input.user.role == "analyst"
    some keyword in analyst_code_keywords
    contains(lower(input.request.prompt), keyword)
}

# ════════════════════════════════════════════════════════
# MODEL ROUTING — phi3:mini everywhere
# Role + risk tiers still enforced, single model backend
# ════════════════════════════════════════════════════════

# Admin, low risk — full access tier
model_route := "phi3:mini" if {
    input.user.role == "admin"
    input.request.risk_score < 0.3
}

# Admin, medium risk — still allowed, same model
model_route := "phi3:mini" if {
    input.user.role == "admin"
    input.request.risk_score >= 0.3
    input.request.risk_score <= 0.7
}

# Analyst, low-medium risk
model_route := "phi3:mini" if {
    input.user.role == "analyst"
    input.request.risk_score < 0.6
}

# Guest — always phi3:mini
model_route := "phi3:mini" if {
    input.user.role == "guest"
}