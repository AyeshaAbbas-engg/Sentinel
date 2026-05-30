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

# ── Security ─────────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "4096"))

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
