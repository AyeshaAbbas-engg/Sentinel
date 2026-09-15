# ════════════════════════════════════════════════════════
# SENTINEL — Intent & Complexity Classifier (Hop 1)
#
# A fast, zero-latency local heuristic classifier that
# assigns every prompt a complexity tier and intent class
# BEFORE the request reaches the LLM backend.
#
# Purpose (per positioning.md):
#   Turns one latency number into a per-hop breakdown and
#   enables cost/quality trade-off routing in a compound
#   FMware pipeline.
#
# Design: pure regex/keyword heuristic — no model call.
# Median latency ≈ 0.1–0.5 ms; adds zero availability risk.
# ════════════════════════════════════════════════════════

import re
import time
from dataclasses import dataclass

from fastapi import HTTPException

from config import CLASSIFIER_MODEL, CLASSIFIER_MAX_TOKENS, CLASSIFIER_TIMEOUT
from backends.ollama import call_ollama

# ── Intent signals ───────────────────────────────────────
_INTENT_RULES: list[tuple[str, str, list[str]]] = [
    # (intent_class, description, keyword_patterns)
    ("code", "code generation / debugging",
     [r"\b(write|generate|create|implement|debug|fix|refactor)\b.{0,40}\b(function|class|code|script|method|api|endpoint|test|program)\b",
      r"\b(python|java|javascript|typescript|rust|go|sql|bash|shell|regex)\b",
      r"\bhow\s+do\s+i\b.{0,30}\b(implement|build|code|write|create)\b"]),

    ("analysis", "analytical / explanatory",
     [r"\b(explain|describe|compare|contrast|analyse|analyze|evaluate|assess|summarize|what\s+is|what\s+are|how\s+does)\b",
      r"\b(difference\s+between|pros\s+and\s+cons|trade.?off|advantage|disadvantage)\b",
      r"\b(architecture|pattern|principle|concept|mechanism|protocol)\b"]),

    ("creative", "creative / generative",
     [r"\b(write\s+a\s+(story|poem|essay|blog|email|message|letter|report))\b",
      r"\b(creative|imaginative|fictional|narrative)\b",
      r"\b(draft|compose|summarize\s+this\s+text)\b"]),

    ("qa", "factual Q&A / lookup",
     [r"^\s*(what|who|where|when|why|which|how)\b",
      r"\b(tell\s+me|can\s+you\s+tell|i\s+want\s+to\s+know)\b",
      r"\b(definition|meaning|overview|introduction)\b"]),
]

# ── Complexity signals ────────────────────────────────────
# Weights add up to a continuous score; tier assigned by threshold.
_COMPLEXITY_TOKENS_SIMPLE   = 30    # below this word count → simple
_COMPLEXITY_TOKENS_COMPLEX  = 120   # above this word count → complex

_COMPLEX_SIGNALS = [
    # multi-step / chain-of-thought requests
    r"\b(step[\s-]by[\s-]step|walk\s+me\s+through|detailed\s+(explanation|breakdown|analysis))\b",
    # asks for examples AND explanations
    r"\b(with\s+examples?)\b.{0,60}\b(explain|describe|show)\b",
    r"\b(compare\s+and\s+contrast|analyse|multi.?hop|complex|advanced|in.?depth)\b",
    # code + tests + docs in one request
    r"\b(unit\s+tests?|docstring|documentation)\b",
    # long structured output
    r"\b(table|diagram|flowchart|architecture\s+diagram|erd)\b",
]

_SIMPLE_SIGNALS = [
    r"^\s*(what\s+is|what\s+are|define|who\s+is|when\s+was)\b.{0,60}$",
    r"^\s*(yes\s+or\s+no|true\s+or\s+false)\b",
    r"^\s*(list\s+(the\s+)?\d+)\b",
]


@dataclass
class ClassifierResult:
    intent_class: str        # qa | code | analysis | creative | other
    complexity_tier: str     # simple | moderate | complex
    confidence: float        # 0.0–1.0 heuristic confidence
    word_count: int
    latency_ms: int
    model: str = "heuristic" # "heuristic" or the LLM model string that decided the tier
    input_tokens: int = 0    # real prompt tokens (LLM classifier hop; 0 for heuristic)
    output_tokens: int = 0   # real completion tokens (LLM classifier hop; 0 for heuristic)


def classify(prompt: str) -> ClassifierResult:
    """
    Classify a prompt into intent class + complexity tier.
    Pure heuristic — no model call. Returns in < 1 ms.
    """
    t0 = time.perf_counter()
    text = prompt.lower().strip()
    words = text.split()
    word_count = len(words)

    # ── Intent classification ────────────────────────────
    intent = "other"
    intent_confidence = 0.0

    for cls, _, patterns in _INTENT_RULES:
        hits = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
        if hits > 0:
            conf = min(1.0, hits / len(patterns) + 0.3)
            if conf > intent_confidence:
                intent = cls
                intent_confidence = conf

    # ── Complexity classification ─────────────────────────
    # Step 1: token-count baseline
    if word_count <= _COMPLEXITY_TOKENS_SIMPLE:
        complexity = "simple"
        complexity_confidence = 0.6
    elif word_count >= _COMPLEXITY_TOKENS_COMPLEX:
        complexity = "complex"
        complexity_confidence = 0.7
    else:
        complexity = "moderate"
        complexity_confidence = 0.5

    # Step 2: signal override
    complex_hits = sum(1 for p in _COMPLEX_SIGNALS
                       if re.search(p, text, re.IGNORECASE))
    simple_hits  = sum(1 for p in _SIMPLE_SIGNALS
                       if re.search(p, text, re.IGNORECASE))

    if complex_hits >= 2:
        complexity = "complex"
        complexity_confidence = min(1.0, 0.5 + complex_hits * 0.15)
    elif complex_hits == 1 and complexity == "simple":
        complexity = "moderate"
        complexity_confidence = 0.55
    elif simple_hits >= 1 and complexity == "moderate":
        complexity = "simple"
        complexity_confidence = 0.65

    latency_ms = max(1, int((time.perf_counter() - t0) * 1000))

    return ClassifierResult(
        intent_class=intent,
        complexity_tier=complexity,
        confidence=round((intent_confidence + complexity_confidence) / 2, 2),
        word_count=word_count,
        latency_ms=latency_ms,
    )


# ════════════════════════════════════════════════════════
# LLM-backed classifier (Hop 1 of the compound pipeline)
# ════════════════════════════════════════════════════════

_CLASSIFIER_PROMPT = (
    "You are a routing classifier. Read the user prompt and reply with EXACTLY ONE "
    "word — SIMPLE, MODERATE, or COMPLEX — describing how much reasoning it needs.\n"
    "SIMPLE = short factual lookup, greeting, or yes/no.\n"
    "MODERATE = a single explanation or one-file code task.\n"
    "COMPLEX = multi-step reasoning, long analysis, or multi-part tasks.\n"
    "Reply with the single word only.\n\n"
    "User prompt:\n{prompt}\n\nAnswer:"
)

_TIER_WORDS = {"SIMPLE": "simple", "MODERATE": "moderate", "COMPLEX": "complex"}


def _parse_tier(raw: str) -> str | None:
    """Extract a complexity tier from the model's raw output; None if absent."""
    up = (raw or "").upper()
    for word, tier in _TIER_WORDS.items():
        if word in up:
            return tier
    return None


async def classify_llm(prompt: str) -> ClassifierResult:
    """
    LLM-backed complexity classifier — hop 1 of the compound pipeline.

    Makes ONE capped call to CLASSIFIER_MODEL (num_predict=CLASSIFIER_MAX_TOKENS,
    temperature=0) and parses SIMPLE/MODERATE/COMPLEX from the output.

    Fail-safe by design: on any backend error/timeout OR unparseable output it
    falls back to the pure-heuristic classify(), so a classifier outage DEGRADES
    the pipeline (still routes + answers) rather than DENYING the request. The
    intent_class always comes from the heuristic — the LLM hop only judges
    complexity. On success the returned result carries the real token usage of
    the classifier call (model + input/output tokens) for per-hop cost.
    """
    # Heuristic first: gives intent_class and a guaranteed fallback tier (<1 ms).
    heur = classify(prompt)

    t0 = time.perf_counter()
    try:
        raw, _llm_ms, prompt_tokens, completion_tokens = await call_ollama(
            _CLASSIFIER_PROMPT.format(prompt=prompt[:1500]),
            CLASSIFIER_MODEL,
            options={"num_predict": CLASSIFIER_MAX_TOKENS, "temperature": 0},
            timeout=CLASSIFIER_TIMEOUT,
        )
    except HTTPException:
        # Backend unreachable / timeout / error → degrade to heuristic.
        heur.latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
        return heur

    tier = _parse_tier(raw)
    latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
    if tier is None:
        # Unparseable output → heuristic tier, but keep the real measured latency.
        heur.latency_ms = latency_ms
        return heur

    return ClassifierResult(
        intent_class=heur.intent_class,
        complexity_tier=tier,
        confidence=0.9,
        word_count=heur.word_count,
        latency_ms=latency_ms,
        model=CLASSIFIER_MODEL,
        input_tokens=prompt_tokens,
        output_tokens=completion_tokens,
    )
