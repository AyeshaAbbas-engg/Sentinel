# ════════════════════════════════════════════════════════
# SENTINEL — Cost Attribution  (v2)
#
# Estimates token counts and per-request USD cost for each
# LLM hop. Because Ollama runs locally no actual money is
# spent, but the estimates reproduce the cost structure of
# cloud-hosted FM APIs — making the numbers directly
# comparable to production deployments and relevant to the
# positioning.md research goal of per-hop cost attribution.
#
# Token counts:
#   When the caller passes Ollama's REAL usage numbers
#   (prompt_eval_count / eval_count) we use them directly — these
#   are the ground-truth token counts. The char/token heuristic
#   below is only a FALLBACK for when measured counts are absent.
#   Heuristic: GPT-family tokenizers average ≈ 4 chars/token for
#   English prose; we use 3.8 (slightly conservative → upper bound).
#
# Pricing reference (small open-source LLM shadow pricing):
#   phi3:mini      input $0.15 / 1M   output $0.60 / 1M
#   qwen2.5:1.5b   input $0.05 / 1M   output $0.20 / 1M
#   Local inference = $0.00 actual; we track shadow cost so the
#   numbers are comparable to cloud FM APIs (hence estimated_cost_usd).
# ════════════════════════════════════════════════════════

from dataclasses import dataclass

# ── Tokenizer heuristic ───────────────────────────────────
_CHARS_PER_TOKEN = 3.8


def estimate_tokens(text: str) -> int:
    """Estimate number of tokens from character count."""
    if not text:
        return 0
    return max(1, round(len(text) / _CHARS_PER_TOKEN))


# ── Per-model pricing  (USD per token) ───────────────────
# Keys must match AVAILABLE_MODELS in router.py.
# Local inference cost = 0 but shadow pricing is tracked.
_MODEL_PRICING: dict[str, dict[str, float]] = {
    "phi3:mini": {
        "input_per_token":  0.15 / 1_000_000,   # $0.15 / 1M
        "output_per_token": 0.60 / 1_000_000,   # $0.60 / 1M
    },
    "qwen2.5:1.5b": {
        "input_per_token":  0.05 / 1_000_000,   # $0.05 / 1M — cheap tier
        "output_per_token": 0.20 / 1_000_000,   # $0.20 / 1M
    },
}

_DEFAULT_PRICING = {
    "input_per_token":  0.15 / 1_000_000,
    "output_per_token": 0.60 / 1_000_000,
}


@dataclass
class CostEstimate:
    model: str
    input_tokens: int
    output_tokens: int
    input_cost_usd: float
    output_cost_usd: float
    total_cost_usd: float


def estimate_cost(
    model: str,
    prompt: str,
    response: str,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> CostEstimate:
    """
    Compute token counts and shadow cost for a single LLM hop.

    When real token counts are supplied (prompt_tokens / completion_tokens
    from the Ollama response) they are used verbatim — the counts are then
    ground truth, not estimates. The char/token heuristic is used only for
    whichever direction was not measured. Only the USD figure remains a
    shadow estimate (hence CostEstimate → estimated_cost_usd).
    """
    pricing = _MODEL_PRICING.get(model, _DEFAULT_PRICING)

    in_tok  = prompt_tokens     if prompt_tokens     is not None else estimate_tokens(prompt)
    out_tok = completion_tokens if completion_tokens is not None else estimate_tokens(response)

    in_cost  = in_tok  * pricing["input_per_token"]
    out_cost = out_tok * pricing["output_per_token"]

    return CostEstimate(
        model=model,
        input_tokens=in_tok,
        output_tokens=out_tok,
        input_cost_usd=in_cost,
        output_cost_usd=out_cost,
        total_cost_usd=in_cost + out_cost,
    )
