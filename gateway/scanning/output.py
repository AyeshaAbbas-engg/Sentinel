import re
import math
from typing import List
from context import RequestContext, Finding

# Secret patterns to detect in model responses
OUTPUT_PATTERNS = [

    # API Keys
    (r"sk-[a-zA-Z0-9]{48}",
     "OpenAI API key detected in response", "critical", 1.0),

    (r"sk-proj-[a-zA-Z0-9\-]{48,}",
     "OpenAI project API key detected", "critical", 1.0),

    # AWS Keys
    (r"AKIA[0-9A-Z]{16}",
     "AWS access key detected in response", "critical", 1.0),

    (r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
     "AWS secret key detected in response", "critical", 1.0),

    # Private Keys
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----",
     "Private key header detected in response", "critical", 1.0),

    (r"-----BEGIN\s+CERTIFICATE-----",
     "Certificate detected in response", "high", 0.6),

    # GitHub/Generic tokens
    (r"ghp_[a-zA-Z0-9]{36}",
     "GitHub personal access token detected", "critical", 1.0),

    (r"github_pat_[a-zA-Z0-9_]{82}",
     "GitHub fine-grained token detected", "critical", 1.0),

    # Internal network paths
    (r"192\.168\.\d{1,3}\.\d{1,3}",
     "Internal IP address in response", "medium", 0.3),

    (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
     "Internal IP address in response", "medium", 0.3),

    (r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
     "Internal IP address in response", "medium", 0.3),

    # Sensitive file paths
    (r"/etc/passwd|/etc/shadow|/etc/hosts",
     "Sensitive Unix file path in response", "high", 0.6),

    (r"/var/log/\w+|/root/\w+|/home/\w+/\.\w+",
     "Sensitive Unix path in response", "medium", 0.4),

    (r"C:\\Windows\\System32|C:\\Users\\\w+\\",
     "Sensitive Windows path in response", "medium", 0.4),

    # Database connection strings
    (r"(mongodb|postgresql|mysql|redis):\/\/[^\s]+:[^\s]+@",
     "Database connection string detected", "critical", 1.0),

    # Generic password patterns
    (r"(?i)password\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*]{8,}['\"]?",
     "Password value detected in response", "high", 0.6),
]


def calculate_entropy(text: str) -> float:
    """
    Shannon entropy — measures randomness of a string.
    High entropy = likely a secret/key (random looking)
    Low entropy = normal text (predictable)
    """
    if not text:
        return 0.0

    # Count character frequencies
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def scan_high_entropy_strings(text: str) -> List[str]:
    """
    Find strings longer than 20 chars with entropy > 4.5
    These are likely secrets/keys/tokens
    """
    suspicious = []
    # Find word-like tokens (no spaces)
    words = re.findall(r'[A-Za-z0-9+/=_\-]{20,}', text)

    for word in words:
        entropy = calculate_entropy(word)
        if entropy > 4.5:
            suspicious.append(word)

    return suspicious


def scan_output(ctx: RequestContext, response_text: str) -> tuple:
    """
    Scans model response for secrets and sensitive data.
    Returns (clean_response, output_blocked, findings)
    """
    blocked = False
    output_findings = []

    # Step 1 — Pattern matching
    for pattern, description, severity, score_delta in OUTPUT_PATTERNS:
        match = re.search(pattern, response_text)
        if match:
            finding = Finding(
                scanner="secret",
                severity=severity,
                description=description,
                matched=match.group(0)[:20] + "...",
                score_delta=score_delta
            )
            output_findings.append(finding)
            ctx.findings.append(finding)

            if severity == "critical":
                blocked = True

    # Step 2 — Entropy check
    suspicious_strings = scan_high_entropy_strings(response_text)
    for s in suspicious_strings:
        finding = Finding(
            scanner="secret",
            severity="high",
            description="High entropy string detected (possible secret)",
            matched=s[:10] + "...",
            score_delta=0.4
        )
        output_findings.append(finding)
        ctx.findings.append(finding)

    # Step 3 — If critical finding → replace response
    if blocked:
        clean_response = "[RESPONSE BLOCKED: Secret or sensitive data detected in model output]"
    else:
        clean_response = response_text

    return clean_response, blocked, output_findings