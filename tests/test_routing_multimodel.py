# ════════════════════════════════════════════════════════
# SENTINEL — Multi-model routing proof (Phase 1)
#
# PURE UNIT test — no gateway server, no Ollama, no OPA.
# Proves that resolve_model() performs REAL multi-model
# selection: the classifier's complexity tier routes
# simple/moderate prompts to the cheap model (qwen2.5:1.5b)
# and complex prompts to phi3:mini, that guests are pinned,
# and that explicit mode never diverts to the cheap model.
#
# Runs standalone:
#     pytest tests/test_routing_multimodel.py
# (Unlike the other tests in this dir, it needs no running stack.)
# ════════════════════════════════════════════════════════

import os
import sys

# Make the gateway package importable without a running container.
_GATEWAY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway"))
if _GATEWAY not in sys.path:
    sys.path.insert(0, _GATEWAY)

from policy.router import resolve_model, AVAILABLE_MODELS, DEFAULT_MODEL  # noqa: E402

CHEAP = "qwen2.5:1.5b"
STANDARD = "phi3:mini"

# The floor OPA returns for every allowed request (see opa/policies/sentinel.rego).
OPA_FLOOR = "phi3:mini"


# ── The second model is really available ─────────────────

def test_second_model_registered():
    assert CHEAP in AVAILABLE_MODELS
    assert AVAILABLE_MODELS[CHEAP] == CHEAP
    assert DEFAULT_MODEL == STANDARD


# ── auto mode: classifier drives the model choice ────────

def test_auto_simple_routes_to_cheap_model():
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "simple", "qa", mode="auto")
    assert d.model == CHEAP


def test_auto_moderate_routes_to_cheap_model():
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "moderate", "analysis", mode="auto")
    assert d.model == CHEAP


def test_auto_complex_routes_to_standard_model():
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "complex", "code", mode="auto")
    assert d.model == STANDARD


def test_auto_admin_simple_routes_to_cheap_model():
    # Non-guest roles all get classifier-driven routing in auto mode.
    d = resolve_model("admin", 0.1, OPA_FLOOR, "simple", "qa", mode="auto")
    assert d.model == CHEAP


# ── Guests are pinned regardless of tier or mode ─────────

def test_guest_pinned_in_auto_mode():
    d = resolve_model("guest", 0.1, OPA_FLOOR, "simple", "qa", mode="auto")
    assert d.model == STANDARD


def test_guest_pinned_even_when_complex():
    d = resolve_model("guest", 0.1, OPA_FLOOR, "complex", "analysis", mode="auto")
    assert d.model == STANDARD


# ── explicit mode: back-compat, never diverted by complexity ─

def test_explicit_simple_does_not_divert_to_cheap_model():
    # A "simple" prompt in EXPLICIT mode must stay on the requested model —
    # this is the byte-compatibility guarantee for existing callers.
    # Pass OPA_FLOOR=phi3 (the normal case).
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "simple", "qa",
                      mode="explicit", requested_model="phi3:mini")
    assert d.model == STANDARD


def test_explicit_ignores_opa_qwen_route():
    # THE REGRESSION TEST: OPA now returns qwen for simple+low-risk non-code.
    # In explicit mode the caller's requested_model must still win — OPA's
    # model_route must NOT divert the caller to the cheap model silently.
    d = resolve_model("analyst", 0.1, "qwen2.5:1.5b", "simple", "qa",
                      mode="explicit", requested_model="phi3:mini")
    assert d.model == STANDARD, (
        "explicit mode must honor requested_model even when OPA returns qwen"
    )


def test_explicit_honors_requested_cheap_model():
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "complex", "code",
                      mode="explicit", requested_model="qwen2.5:1.5b")
    assert d.model == CHEAP


def test_explicit_unknown_model_falls_back_to_default():
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "moderate", "qa",
                      mode="explicit", requested_model="mistral:7b")
    assert d.model == DEFAULT_MODEL


# ── Blocked passthrough is preserved ─────────────────────

def test_blocked_route_passthrough():
    d = resolve_model("analyst", 0.95, "BLOCKED", "complex", "code", mode="auto")
    assert d.model == "BLOCKED"
    assert d.tier == "blocked"


def test_auto_elevated_risk_simple_respects_opa_phi3():
    # THE SECOND REGRESSION TEST: elevated-risk simple prompt.
    # OPA returns phi3 (its "simple+elevated-risk → standard" rule).
    # In auto mode OPA is authoritative — COMPLEXITY_MODEL_MAP must NOT
    # override OPA's risk-based decision and send it to cheap qwen.
    d = resolve_model("admin", 0.5, "phi3:mini", "simple", "qa",
                      mode="auto", requested_model="auto")
    assert d.model == STANDARD
    d2 = resolve_model("admin", 0.1, "qwen2.5:1.5b", "simple", "qa",
                       mode="auto", requested_model="auto")
    assert d2.model == CHEAP, "auto mode: OPA named qwen → use qwen"


# ── Default signature stays backward compatible ──────────

def test_legacy_call_signature_still_works():
    # Old callers passed no mode/requested_model → defaults to explicit.
    d = resolve_model("analyst", 0.1, OPA_FLOOR, "simple", "qa")
    assert d.model in AVAILABLE_MODELS.values()
