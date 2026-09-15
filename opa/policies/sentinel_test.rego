package sentinel.authz_test

import rego.v1

# ── helper: a base request with all v2 fields present ────
# Existing tests keep passing because complexity_tier="unknown"
# leaves all the new complexity/intent rules inactive.
base_request(role, risk, pii, prompt, model) := {
    "user": {
        "id":                   "u_test",
        "role":                 role,
        "requests_last_minute": 1,
    },
    "request": {
        "risk_score":        risk,
        "pii_detected":      pii,
        "injection_detected": false,
        "prompt":            prompt,
        "requested_model":   model,
        "complexity_tier":   "unknown",
        "intent_class":      "other",
    },
}

# ════════════════════════════════════════════════════════
# POLICY 1 — Risk Score Hard Block
# ════════════════════════════════════════════════════════

test_high_risk_blocked if {
    not data.sentinel.authz.allow
        with input as base_request("admin", 0.85, false, "hello", "phi3:mini")
}

test_low_risk_allowed if {
    data.sentinel.authz.allow
        with input as base_request("admin", 0.1, false, "what is 2+2", "phi3:mini")
}

test_boundary_risk_exactly_07_allowed if {
    # 0.7 exactly is NOT above threshold — should allow
    data.sentinel.authz.allow
        with input as base_request("analyst", 0.7, false, "summarize this", "phi3:mini")
}

# ════════════════════════════════════════════════════════
# POLICY 2 — PII + Non-Admin Block
# ════════════════════════════════════════════════════════

test_pii_blocked_for_analyst if {
    not data.sentinel.authz.allow
        with input as base_request("analyst", 0.2, true, "my email is test@test.com", "phi3:mini")
}

test_pii_blocked_for_guest if {
    not data.sentinel.authz.allow
        with input as base_request("guest", 0.2, true, "my name is John", "phi3:mini")
}

test_pii_allowed_for_admin if {
    data.sentinel.authz.allow
        with input as base_request("admin", 0.2, true, "my email is test@test.com", "phi3:mini")
}

# ════════════════════════════════════════════════════════
# POLICY 3 — Guest Model Restriction
# ════════════════════════════════════════════════════════

test_guest_phi3_allowed if {
    data.sentinel.authz.allow
        with input as base_request("guest", 0.0, false, "hello", "phi3:mini")
}

test_guest_other_model_blocked if {
    not data.sentinel.authz.allow
        with input as base_request("guest", 0.0, false, "hello", "mistral:7b")
}

# ════════════════════════════════════════════════════════
# POLICY 4 — Analyst Rate Limit
# ════════════════════════════════════════════════════════

test_analyst_rate_limit_exceeded if {
    not data.sentinel.authz.allow with input as {
        "user": {
            "id": "u_006", "role": "analyst",
            "requests_last_minute": 21,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false, "prompt": "summarize this",
            "requested_model": "phi3:mini",
            "complexity_tier": "unknown", "intent_class": "other",
        },
    }
}

test_analyst_rate_limit_within_bounds if {
    data.sentinel.authz.allow with input as {
        "user": {
            "id": "u_006", "role": "analyst",
            "requests_last_minute": 15,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false, "prompt": "summarize this",
            "requested_model": "phi3:mini",
            "complexity_tier": "unknown", "intent_class": "other",
        },
    }
}

# ════════════════════════════════════════════════════════
# POLICY 5 — Analyst Code-Execution Gate
# ════════════════════════════════════════════════════════

test_analyst_bash_blocked if {
    not data.sentinel.authz.allow
        with input as base_request("analyst", 0.0, false, "write a bash script to list files", "phi3:mini")
}

test_analyst_normal_prompt_allowed if {
    data.sentinel.authz.allow
        with input as base_request("analyst", 0.0, false, "summarize last quarter sales report", "phi3:mini")
}

test_admin_code_allowed if {
    # Admin is not restricted by code gate
    data.sentinel.authz.allow
        with input as base_request("admin", 0.0, false, "write a bash script to list files", "phi3:mini")
}

# ════════════════════════════════════════════════════════
# POLICY 6 — Per-hop governance: guest complex-code block (NEW)
# ════════════════════════════════════════════════════════

test_guest_complex_code_blocked if {
    not data.sentinel.authz.allow with input as {
        "user": {
            "id": "u_guest", "role": "guest",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false,
            "prompt": "write a full microservices architecture with tests and docs",
            "requested_model": "phi3:mini",
            "complexity_tier": "complex",
            "intent_class":    "code",
        },
    }
}

test_guest_simple_code_allowed if {
    # simple code + guest is fine — only complex code is gated
    data.sentinel.authz.allow with input as {
        "user": {
            "id": "u_guest", "role": "guest",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false,
            "prompt": "write a hello world in python",
            "requested_model": "phi3:mini",
            "complexity_tier": "simple",
            "intent_class":    "code",
        },
    }
}

test_guest_complex_non_code_allowed if {
    # complex analysis (not code) is not gated for guests
    data.sentinel.authz.allow with input as {
        "user": {
            "id": "u_guest", "role": "guest",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false,
            "prompt": "explain the history of the Byzantine Empire in detail",
            "requested_model": "phi3:mini",
            "complexity_tier": "complex",
            "intent_class":    "analysis",
        },
    }
}

test_admin_complex_code_allowed if {
    # rule 6 is guest-only — admin can do complex code
    data.sentinel.authz.allow with input as {
        "user": {
            "id": "u_admin", "role": "admin",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false,
            "prompt": "design a distributed system with full test suite",
            "requested_model": "phi3:mini",
            "complexity_tier": "complex",
            "intent_class":    "code",
        },
    }
}

# ════════════════════════════════════════════════════════
# MODEL ROUTING — v2 complexity-aware (NEW)
# ════════════════════════════════════════════════════════

test_model_route_simple_low_risk_is_cheap if {
    data.sentinel.authz.model_route == "qwen2.5:1.5b" with input as {
        "user": {
            "id": "u_analyst", "role": "analyst",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.1, "pii_detected": false,
            "injection_detected": false,
            "prompt": "what is 2+2",
            "requested_model": "phi3:mini",
            "complexity_tier": "simple",
            "intent_class":    "qa",
        },
    }
}

test_model_route_moderate_low_risk_is_cheap if {
    data.sentinel.authz.model_route == "qwen2.5:1.5b" with input as {
        "user": {
            "id": "u_admin", "role": "admin",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.2, "pii_detected": false,
            "injection_detected": false,
            "prompt": "explain what a VPN is",
            "requested_model": "phi3:mini",
            "complexity_tier": "moderate",
            "intent_class":    "analysis",
        },
    }
}

test_model_route_complex_is_standard if {
    data.sentinel.authz.model_route == "phi3:mini" with input as {
        "user": {
            "id": "u_admin", "role": "admin",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.1, "pii_detected": false,
            "injection_detected": false,
            "prompt": "design a distributed system",
            "requested_model": "phi3:mini",
            "complexity_tier": "complex",
            "intent_class":    "analysis",
        },
    }
}

test_model_route_code_intent_is_standard if {
    # code intent always routes to standard model
    data.sentinel.authz.model_route == "phi3:mini" with input as {
        "user": {
            "id": "u_admin", "role": "admin",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.1, "pii_detected": false,
            "injection_detected": false,
            "prompt": "write a python function",
            "requested_model": "phi3:mini",
            "complexity_tier": "simple",
            "intent_class":    "code",
        },
    }
}

test_model_route_guest_always_standard if {
    data.sentinel.authz.model_route == "phi3:mini" with input as {
        "user": {
            "id": "u_guest", "role": "guest",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.0, "pii_detected": false,
            "injection_detected": false,
            "prompt": "what is 2+2",
            "requested_model": "phi3:mini",
            "complexity_tier": "simple",
            "intent_class":    "qa",
        },
    }
}

test_model_route_elevated_risk_simple_is_standard if {
    # simple prompt but risk > 0.3 → standard model
    data.sentinel.authz.model_route == "phi3:mini" with input as {
        "user": {
            "id": "u_admin", "role": "admin",
            "requests_last_minute": 1,
        },
        "request": {
            "risk_score": 0.5, "pii_detected": false,
            "injection_detected": false,
            "prompt": "what is 2+2",
            "requested_model": "phi3:mini",
            "complexity_tier": "simple",
            "intent_class":    "qa",
        },
    }
}
