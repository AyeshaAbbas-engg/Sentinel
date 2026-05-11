import re
from context import RequestContext, Finding

INJECTION_PATTERNS = [
    (r"ignore\s+(previous|prior|all|above)\s+(instructions?|prompts?|context)",
     "Instruction override attempt", "critical", 0.8),
    (r"disregard\s+(previous|prior|all|above|your)",
     "Instruction disregard attempt", "critical", 0.8),
    (r"forget\s+(everything|all|your|previous|prior)",
     "Memory wipe attempt", "critical", 0.8),
    (r"do\s+not\s+follow\s+(your|previous|prior|the)\s+instructions?",
     "Instruction negation attempt", "critical", 0.8),
    (r"you\s+are\s+now\s+(a|an|the)\s+\w+",
     "Role reassignment attempt", "high", 0.6),
    (r"act\s+as\s+(a|an|the)?\s*\w+\s*(with\s+no|without)\s+\w+",
     "Unrestricted role attempt", "high", 0.6),
    (r"pretend\s+(you\s+have\s+no|you\s+are\s+not|there\s+are\s+no)",
     "Restriction bypass attempt", "high", 0.6),
    (r"(DAN|jailbreak|developer\s+mode|god\s+mode)\s*(mode|prompt|enabled)?",
     "Known jailbreak keyword", "high", 0.6),
    (r"you\s+have\s+no\s+(restrictions?|limits?|rules?|guidelines?)",
     "Restriction denial", "high", 0.6),
    (r"(reveal|show|print|display|output|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|prompt|guidelines?)",
     "System prompt extraction attempt", "high", 0.6),
    (r"what\s+(are|were)\s+your\s+(instructions?|guidelines?|rules?|system\s+prompt)",
     "Instruction extraction attempt", "high", 0.6),
    (r"repeat\s+(everything|all|your\s+instructions?)\s+(above|before|previously)",
     "Prompt repetition attack", "high", 0.6),
    (r"[A-Za-z0-9+/]{50,}={0,2}",
     "Possible base64 encoded payload", "medium", 0.4),
    (r"(0x[0-9a-fA-F]{2}\s*){8,}",
     "Hex encoded content detected", "medium", 0.4),
    (r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>|<\/s>",
     "Model-specific injection token", "medium", 0.4),
    (r"###\s*(instruction|system|human|assistant|input|output)\s*:",
     "Prompt template injection", "medium", 0.4),
    (r"my\s+(grandmother|grandma|mother|mom|father|dad)\s+used\s+to",
     "Social engineering via nostalgia", "low", 0.2),
    (r"for\s+(educational|research|academic|training)\s+purposes?",
     "Educational framing bypass", "low", 0.2),
    (r"hypothetically\s+(speaking|if|assuming)",
     "Hypothetical framing bypass", "low", 0.2),
    (r"in\s+a\s+(fictional|fantasy|story|movie|game)\s+(world|setting|scenario)",
     "Fictional framing bypass", "low", 0.2),
    (r"(pretend|imagine|suppose)\s+(this\s+is\s+)?(just\s+)?(a\s+)?(game|story|fiction|test)",
     "Fictional context bypass", "low", 0.2),
]

def scan_injection(ctx: RequestContext) -> RequestContext:
    """
    Scans clean_prompt for injection patterns.
    Adds findings — risk score computed by risk.py
    """
    text = ctx.clean_prompt.lower()

    for pattern, description, severity, score_delta in INJECTION_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            finding = Finding(
                scanner="injection",
                severity=severity,
                description=description,
                matched=match.group(0)[:50],
                score_delta=score_delta
                # NOTE: risk_score NOT updated here — risk.py does it
            )
            ctx.findings.append(finding)

    return ctx