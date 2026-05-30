import re
from context import RequestContext, Finding
from scanning.sanitize import normalize_text

INJECTION_PATTERNS = [

    # ── CRITICAL: Direct instruction override ────────────────────────────
    (r"ignore\s+(previous|prior|all|above)\s+(instructions?|prompts?|context)",
     "Instruction override attempt", "critical", 0.8),
    (r"disregard\s+(previous|prior|all|above|your)(\s+\w+){0,3}\s*(instructions?|prompts?|context|filters?)?",
     "Instruction disregard attempt", "critical", 0.8),
    (r"forget\s+(everything|all|your|previous|prior)",
     "Memory wipe attempt", "critical", 0.8),
    (r"do\s+not\s+follow\s+(your|previous|prior|the)\s+instructions?",
     "Instruction negation attempt", "critical", 0.8),
    (r"repeat\s+(everything|all|your\s+instructions?)\s+(above|before|previously)",
     "Prompt repetition attack", "critical", 0.8),

    # ── CRITICAL: Known jailbreak modes ─────────────────────────────────
    (r"\bDAN\b\s*(mode|enabled|prompt)?",
     "DAN jailbreak attempt", "critical", 0.9),
    (r"(developer\s+mode|god\s+mode)\s*(enabled|activated|prompt|:)?",
     "Developer/God mode jailbreak", "critical", 0.9),
    (r"jailbreak\s*(mode|prompt|enabled)?",
     "Jailbreak keyword detected", "critical", 0.9),
    (r"all\s+restrictions?\s+are\s+(lifted|removed|disabled|gone)",
     "Restriction removal claim", "critical", 0.8),

    # ── CRITICAL: Role/identity reassignment (BOUNDED to prevent backtracking) ──
    (r"you\s+are\s+now\s+(a|an|the)\s+[\w\s]{1,40}",
     "Role reassignment attempt", "critical", 0.8),
    (r"act\s+as\s+(a|an|the)?\s*[\w\s]{1,30}(with\s+no|without)\s+[\w\s]{1,30}",
     "Unrestricted role attempt", "critical", 0.8),
    (r"(you\s+are|act\s+as)\s+(an?\s+)?(unfiltered|unrestricted|uncensored)\s+(ai|assistant|model|chatbot)",
     "Unrestricted AI persona attempt", "critical", 0.9),

    # ── CRITICAL: System prompt extraction ──────────────────────────────
    (r"(reveal|show|print|display|output|tell\s+me|repeat|expose)\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions?|guidelines?|configuration)",
     "System prompt extraction attempt", "critical", 0.8),
    (r"what\s+(are|were)\s+your\s+(instructions?|guidelines?|rules?|system\s+prompt)",
     "Instruction extraction attempt", "critical", 0.8),
    (r"print\s+(them\s+)?(verbatim|exactly|word\s+for\s+word)",
     "Verbatim extraction attempt", "critical", 0.8),
    (r"output\s+your\s+(full\s+)?(configuration|config|system|setup|prompt)",
     "Configuration extraction attempt", "critical", 0.9),

    # ── HIGH: Restriction bypass framing ────────────────────────────────
    (r"pretend\s+(you\s+have\s+no|you\s+are\s+not|there\s+are\s+no|this\s+is\s+just)",
     "Restriction bypass via pretend", "high", 0.7),
    (r"you\s+have\s+no\s+(restrictions?|limits?|rules?|guidelines?|content\s+policy|safety)",
     "Restriction denial", "high", 0.7),
    (r"no\s+(restrictions?|limits?|rules?|guidelines?|filters?|safety\s+measures?)",
     "Explicit restriction denial", "high", 0.7),
    (r"(ignore|bypass|override|disable)\s+(your\s+)?(safety|filter|content\s+policy|guidelines?|restrictions?|rules?)",
     "Safety bypass attempt", "high", 0.8),

    # ── HIGH: Fictional/hypothetical framing bypass ──────────────────────
    (r"hypothetically\s+(speaking|if|assuming|what\s+if)",
     "Hypothetical framing bypass", "high", 0.6),
    (r"in\s+a\s+(fictional|fantasy|story|movie|game|hypothetical)\s+(world|setting|scenario|universe)",
     "Fictional world framing bypass", "high", 0.6),
    (r"(pretend|imagine|suppose)\s+(this\s+is\s+)?(just\s+)?(a\s+)?(game|story|fiction|test|simulation|roleplay)",
     "Fictional context bypass", "high", 0.6),
    (r"if\s+you\s+(had\s+no|didn.t\s+have|were\s+without)\s+(restrictions?|filters?|guidelines?|rules?)",
     "Conditional restriction bypass", "high", 0.6),

    # ── HIGH: Social engineering ─────────────────────────────────────────
    (r"my\s+(grandmother|grandma|mother|mom|father|dad|uncle|aunt)\s+used\s+to\s+(tell|read|say)",
     "Social engineering via nostalgia (grandma exploit)", "high", 0.6),
    (r"(bedtime\s+story|used\s+to\s+tell\s+me).{0,50}(bypass|safety|filter|jailbreak|hack|override)",
     "Grandma exploit with harmful intent", "high", 0.7),

    # ── HIGH: Encoded attacks (score bumped to ensure block) ─────────────
    (r"[A-Za-z0-9+/]{50,}={0,2}",
     "Possible base64 encoded payload", "high", 0.8),
    (r"(0x[0-9a-fA-F]{2}\s*){8,}",
     "Hex encoded content detected", "high", 0.8),

    # ── HIGH: Model token injection ──────────────────────────────────────
    (r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>|<\/s>",
     "Model-specific injection token", "high", 0.7),
    (r"###\s*(instruction|system|human|assistant|input|output)\s*:",
     "Prompt template injection", "high", 0.8),

    # ── HIGH: Shell/system command attacks ───────────────────────────────
    (r"(write|create|generate|give\s+me)\s+a?\s*(bash|shell|sh|zsh|python|powershell|cmd)\s+script",
     "Script generation attempt", "high", 0.8),
    (r"(execute|run|eval)\s+(this\s+)?(shell\s+)?(command|script|code)",
     "Command execution attempt", "critical", 0.9),
    (r"(rm\s+-rf|chmod\s+[0-9]+|sudo\s+\w+|curl\s+.{1,50}\|\s*(ba)?sh|wget\s+.{1,50}\|\s*(ba)?sh)",
     "Dangerous shell command", "critical", 0.9),
    (r"(\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/proc\/self|\/root\/)",
     "Sensitive system path reference", "critical", 0.9),
    (r"(subprocess|os\.system|os\.popen|exec\(|eval\(|__import__)",
     "Code execution function reference", "critical", 0.9),
    (r"enumerate\s+(the\s+)?(network|hosts?|ports?|services?)",
     "Network enumeration attempt", "high", 0.8),

    # ── HIGH: Attack demonstration requests ──────────────────────────────
    (r"(demonstrate|show\s+me|explain\s+how)\s+(a\s+)?(sql\s+injection|xss|exploit|payload|attack|hack)",
     "Attack demonstration request", "high", 0.8),

    # ── MEDIUM: Educational/research framing ─────────────────────────────
    (r"for\s+(purely\s+|basically\s+|strictly\s+)?(educational|research|academic|training|demonstration)\s+purposes?",
     "Educational framing bypass", "medium", 0.4),

    # ── MEDIUM: Confirmation bypass ──────────────────────────────────────
    (r"confirm\s+(by\s+saying|with\s+the\s+word|by\s+responding)\s+[\"\']?\w+[\"\']?",
     "Confirmation bypass attempt", "medium", 0.4),
    (r"(say|respond\s+with|output|print)\s+[\"\']?(UNLOCKED|JAILBROKEN|CONFIRMED|ACTIVATED)[\"\']?",
     "Activation keyword request", "medium", 0.5),
]

# ── Token-split bypass keywords ──────────────────────────────────────────────
_SPLIT_KEYWORDS = [
    "ignore previous", "disregard instructions", "forget everything",
    "system prompt", "jailbreak", "developer mode", "god mode",
    "no restrictions", "act as", "you are now", "override safety",
    "bypass filter", "unrestricted ai",
]


def _detect_token_splitting(text: str) -> list:
    """Detect keywords split with separators like 'i.g.n.o.r.e' or 'i g n o r e'."""
    findings = []
    collapsed = re.sub(r'[\s.\-_*|/\\]+', '', text.lower())
    for keyword in _SPLIT_KEYWORDS:
        clean_kw = keyword.replace(" ", "")
        if clean_kw in collapsed and keyword not in text.lower():
            findings.append(Finding(
                scanner="injection",
                severity="critical",
                description=f"Token-split bypass detected: '{keyword}'",
                matched=keyword,
                score_delta=0.8
            ))
    return findings


def scan_injection(ctx: RequestContext) -> RequestContext:
    """Multi-layer injection scan: normalize → regex → token-split detection."""
    normalized = normalize_text(ctx.clean_prompt).lower()

    for pattern, description, severity, score_delta in INJECTION_PATTERNS:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            ctx.findings.append(Finding(
                scanner="injection",
                severity=severity,
                description=description,
                matched=match.group(0)[:50],
                score_delta=score_delta
            ))

    ctx.findings.extend(_detect_token_splitting(ctx.clean_prompt))

    return ctx