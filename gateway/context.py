from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict


@dataclass
class Finding:
    scanner: str
    severity: str
    description: str
    matched: str
    score_delta: float


@dataclass
class HopRecord:
    """Timing + metadata for a single named pipeline hop."""
    name: str           # e.g. "classifier", "llm_backend"
    latency_ms: int
    model: Optional[str] = None   # populated for model hops
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    status: str = "ok"            # ok | blocked | error | skipped


@dataclass
class RequestContext:
    request_id: str
    user_id: str
    role: str
    raw_prompt: str
    clean_prompt: str
    risk_score: float = 0.0
    findings: list = field(default_factory=list)
    policy_decision: str = ""
    policy_reason: str = ""
    model_used: str = ""
    latency_ms: int = 0
    requests_last_minute: int = 0
    timestamp: str = ""

    # ── Multi-hop instrumentation ────────────────────────
    # hop_timings: ordered list of HopRecord objects, one per named stage
    hop_timings: List[HopRecord] = field(default_factory=list)

    # ── Cost attribution ─────────────────────────────────
    input_tokens: int = 0          # estimated tokens sent to LLM(s)
    output_tokens: int = 0         # estimated tokens received from LLM(s)
    estimated_cost_usd: float = 0.0

    # ── Classifier output (hop-1 result) ─────────────────
    complexity_tier: str = "unknown"   # simple | moderate | complex
    intent_class: str = "unknown"      # qa | code | analysis | creative | other

    def record_hop(self, name: str, latency_ms: int, **kwargs) -> None:
        """Append a HopRecord. Extra kwargs passed through to HopRecord."""
        self.hop_timings.append(HopRecord(name=name, latency_ms=latency_ms, **kwargs))
