import os
import sys

def _require(var: str) -> str:
    val = os.getenv(var)
    if not val:
        print(f"FATAL: Required environment variable '{var}' is not set. Exiting.", file=sys.stderr)
        sys.exit(1)
    return val

# ── Required ─────────────────────────────────────────────
JWT_SECRET = _require("JWT_SECRET")

# ── Services ─────────────────────────────────────────────
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://presidio:8001")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181")

# ── Models (multi-model routing) ─────────────────────────
# CLASSIFIER_MODEL runs hop-1 (capped complexity classification).
# CHEAP_MODEL serves simple/moderate prompts; STANDARD_MODEL is the
# default generation model and the guest-pinned model.
CLASSIFIER_MODEL      = os.getenv("CLASSIFIER_MODEL", "qwen2.5:1.5b")
CHEAP_MODEL           = os.getenv("CHEAP_MODEL", "qwen2.5:1.5b")
STANDARD_MODEL        = os.getenv("STANDARD_MODEL", "phi3:mini")
CLASSIFIER_MAX_TOKENS = int(os.getenv("CLASSIFIER_MAX_TOKENS", "5"))
CLASSIFIER_TIMEOUT    = int(os.getenv("CLASSIFIER_TIMEOUT", "20"))  # short → degrade fast

# ── Security ─────────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "4096"))
# The token issuer exists solely to make the local demo and benchmark
# self-contained.  A deployed gateway must receive tokens from its identity
# provider, so keep this explicitly opt-in outside development.
ENABLE_DEMO_TOKEN_ENDPOINT = os.getenv("ENABLE_DEMO_TOKEN_ENDPOINT", "false").lower() == "true"

# ── Rate Limits ──────────────────────────────────────────
RATE_LIMITS = {
    "admin": int(os.getenv("RATE_LIMIT_ADMIN", "60")),
    "analyst": int(os.getenv("RATE_LIMIT_ANALYST", "20")),
    "guest": int(os.getenv("RATE_LIMIT_GUEST", "5")),
}
RATE_WINDOW_SECONDS = int(os.getenv("RATE_WINDOW_SECONDS", "60"))

# ── Timeouts ─────────────────────────────────────────────
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))
PRESIDIO_TIMEOUT = int(os.getenv("PRESIDIO_TIMEOUT", "30"))
OPA_TIMEOUT = int(os.getenv("OPA_TIMEOUT", "10"))

# ── Logging ──────────────────────────────────────────────
LOG_DIR = os.getenv("LOG_DIR", "/app/logs")
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

# ── Algorithm ────────────────────────────────────────────
JWT_ALGORITHM = "HS256"
