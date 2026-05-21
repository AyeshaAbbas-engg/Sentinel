package sentinel.authz_test

import rego.v1

# ════════════════════════════════════════════════════════
# POLICY 1 TESTS — Risk Score Hard Block
# ════════════════════════════════════════════════════════

test_high_risk_blocked if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_001", "role": "admin", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.85,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "hello",
            "requested_model": "phi3:mini"
        }
    }
    result == false
}

test_low_risk_allowed if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_001", "role": "admin", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.1,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "what is 2+2",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}

test_boundary_risk_exactly_07_allowed if {
    # 0.7 exactly is NOT above threshold — should allow
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_001", "role": "analyst", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.7,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "summarize this",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}

# ════════════════════════════════════════════════════════
# POLICY 2 TESTS — PII + Non-Admin Block
# ════════════════════════════════════════════════════════

test_pii_blocked_for_analyst if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_002", "role": "analyst", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.2,
            "pii_detected": true,
            "injection_detected": false,
            "prompt": "my email is test@test.com",
            "requested_model": "phi3:mini"
        }
    }
    result == false
}

test_pii_blocked_for_guest if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_003", "role": "guest", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.2,
            "pii_detected": true,
            "injection_detected": false,
            "prompt": "my name is John",
            "requested_model": "phi3:mini"
        }
    }
    result == false
}

test_pii_allowed_for_admin if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_004", "role": "admin", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.2,
            "pii_detected": true,
            "injection_detected": false,
            "prompt": "my email is test@test.com",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}

# ════════════════════════════════════════════════════════
# POLICY 3 TESTS — Guest Model Restriction
# ════════════════════════════════════════════════════════

test_guest_phi3_allowed if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_005", "role": "guest", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "hello",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}

test_guest_other_model_blocked if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_005", "role": "guest", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "hello",
            "requested_model": "mistral:7b"
        }
    }
    result == false
}

# ════════════════════════════════════════════════════════
# POLICY 4 TESTS — Analyst Rate Limit
# ════════════════════════════════════════════════════════

test_analyst_rate_limit_exceeded if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_006", "role": "analyst", "requests_last_minute": 21},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "summarize this",
            "requested_model": "phi3:mini"
        }
    }
    result == false
}

test_analyst_rate_limit_within_bounds if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_006", "role": "analyst", "requests_last_minute": 15},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "summarize this",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}

# ════════════════════════════════════════════════════════
# POLICY 5 TESTS — Analyst Code Execution Gate
# ════════════════════════════════════════════════════════

test_analyst_bash_blocked if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_007", "role": "analyst", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "write a bash script to list files",
            "requested_model": "phi3:mini"
        }
    }
    result == false
}

test_analyst_normal_prompt_allowed if {
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_007", "role": "analyst", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "summarize last quarter sales report",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}

test_admin_code_allowed if {
    # Admin is not restricted by code gate
    result := data.sentinel.authz.allow with input as {
        "user": {"id": "u_008", "role": "admin", "requests_last_minute": 1},
        "request": {
            "risk_score": 0.0,
            "pii_detected": false,
            "injection_detected": false,
            "prompt": "write a bash script to list files",
            "requested_model": "phi3:mini"
        }
    }
    result == true
}