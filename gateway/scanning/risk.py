from typing import Tuple
from context import RequestContext, Finding

# Risk thresholds
THRESHOLD_LOW = 0.3
THRESHOLD_MEDIUM = 0.6
THRESHOLD_HIGH = 0.8

# Per-scanner caps — no single scanner can dominate the score
SCANNER_CAPS = {
    "pii":       0.6,
    "injection": 1.0,  # injection can reach max
    "secret":    1.0,  # output secrets can reach max
    "anomaly":   0.5,
}

def compute_risk_score(ctx: RequestContext) -> RequestContext:
    """
    Aggregates all findings into a final risk score.
    Applies per-scanner caps then sums.
    Determines risk level and recommended action.
    """

    # Group findings by scanner
    scanner_scores = {}
    for finding in ctx.findings:
        scanner = finding.scanner
        if scanner not in scanner_scores:
            scanner_scores[scanner] = 0.0
        scanner_scores[scanner] += finding.score_delta

    # Apply per-scanner caps
    capped_scores = {}
    for scanner, score in scanner_scores.items():
        cap = SCANNER_CAPS.get(scanner, 0.5)
        capped_scores[scanner] = min(cap, score)

    # Final score = sum of all capped scanner scores, max 1.0
    final_score = min(1.0, sum(capped_scores.values()))
    ctx.risk_score = final_score

    return ctx


def get_risk_level(score: float) -> str:
    """Returns human readable risk level"""
    if score < THRESHOLD_LOW:
        return "low"
    elif score < THRESHOLD_MEDIUM:
        return "medium"
    elif score < THRESHOLD_HIGH:
        return "high"
    else:
        return "critical"


def should_block(score: float, role: str) -> Tuple[bool, str]:
    """
    Decides if request should be blocked based on
    risk score AND user role.
    Returns (block: bool, reason: str)
    """
    level = get_risk_level(score)

    if level == "critical":
        return True, f"Critical risk score {score:.2f} — blocked for all roles"

    if level == "high":
        if role in ["guest", "analyst"]:
            return True, f"High risk score {score:.2f} — blocked for role '{role}'"
        else:
            # Admin gets flagged but not blocked
            return False, f"High risk score {score:.2f} — flagged for admin review"

    if level == "medium":
        if role == "guest":
            return False, f"Medium risk — guest allowed with extra scrutiny"
        return False, f"Medium risk — within acceptable range"

    return False, "Low risk — allowed"