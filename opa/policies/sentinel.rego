package sentinel.authz

import rego.v1

# ════════════════════════════════════════════════════════
# DEFAULTS
# ════════════════════════════════════════════════════════

default allow := false
default model_route := "phi3:mini"

# ════════════════════════════════════════════════════════
# ALLOW RULE
# ════════════════════════════════════════════════════════

allow if {
    count(deny_reasons) == 0
}

# ════════════════════════════════════════════════════════
# REASON — uses else to avoid multiple outputs
# ════════════════════════════════════════════════════════

reason := concat("; ", deny_reasons) if {
    count(deny_reasons) > 0
} else := "all checks passed"

# ════════════════════════════════════════════════════════
# DENY REASONS SET
# ════════════════════════════════════════════════════════

deny_reasons contains sprintf("risk score %.2f exceeds threshold 0.7", [input.request.risk_score]) if {
    input.request.risk_score > 0.7
}

deny_reasons contains "PII detected — only admins may send PII prompts" if {
    input.request.pii_detected == true
    input.user.role != "admin"
}

deny_reasons contains "guests are restricted to phi3:mini only" if {
    input.user.role == "guest"
    input.request.requested_model != "phi3:mini"
}

deny_reasons contains "rate limit exceeded for analyst role" if {
    input.user.role == "analyst"
    input.user.requests_last_minute > 20
}

deny_reasons contains "code execution not permitted for analyst role" if {
    input.user.role == "analyst"
    some keyword in analyst_code_keywords
    contains(lower(input.request.prompt), keyword)
}

# ════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════

denied if {
    count(deny_reasons) > 0
}

analyst_code_keywords := ["execute", "run code", "bash", "subprocess", "shell", "os.system"]

# ════════════════════════════════════════════════════════
# MODEL ROUTING
# ════════════════════════════════════════════════════════

model_route := "phi3:mini" if {
    input.user.role == "admin"
    input.request.risk_score < 0.3
}

model_route := "phi3:mini" if {
    input.user.role == "admin"
    input.request.risk_score >= 0.3
    input.request.risk_score <= 0.7
}

model_route := "phi3:mini" if {
    input.user.role == "analyst"
    input.request.risk_score <= 0.7
}

model_route := "phi3:mini" if {
    input.user.role == "guest"
}
