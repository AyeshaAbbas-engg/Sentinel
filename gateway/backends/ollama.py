# ════════════════════════════════════════════════════════
# SENTINEL — Ollama Backend  (v2: per-hop metrics + real tokens)
#
# Changes from v1:
#   - Records sentinel_backend_latency_ms histogram per model
#   - Increments sentinel_backend_timeout_total on 504
#   - Increments sentinel_backend_error_total on other errors
#   - Returns (response_text, latency_ms, prompt_tokens,
#     completion_tokens) so callers get Ollama's REAL token
#     usage (prompt_eval_count / eval_count) for honest cost
#     attribution — not a char-count estimate.
#   - Accepts an optional `options` dict (e.g. num_predict) so
#     the capped classifier hop can bound its output, and an
#     optional per-call `timeout` override.
# ════════════════════════════════════════════════════════

import time
import httpx
from fastapi import HTTPException
from config import OLLAMA_URL, OLLAMA_TIMEOUT
from observability.metrics import (
    record_backend_latency,
    record_backend_timeout,
    record_backend_error,
)


async def call_ollama(
    prompt: str,
    model: str,
    options: dict | None = None,
    timeout: float | None = None,
) -> tuple[str, int, int, int]:
    """
    Call Ollama LLM backend.

    Args:
        prompt:  prompt text
        model:   Ollama model string
        options: optional Ollama `options` dict (e.g.
                 {"num_predict": 5, "temperature": 0}) used by the
                 capped classifier hop
        timeout: optional per-call timeout override (seconds);
                 defaults to OLLAMA_TIMEOUT

    Returns:
        (response_text, latency_ms, prompt_tokens, completion_tokens)
        Token counts are Ollama's real usage (prompt_eval_count /
        eval_count); 0 only if the backend omits them.

    Raises:
        HTTPException 504 on timeout
        HTTPException 503 on connection error
        HTTPException 502 on other backend errors
    """
    payload: dict = {"model": model, "prompt": prompt, "stream": False}
    if options:
        payload["options"] = options
    effective_timeout = float(timeout) if timeout is not None else float(OLLAMA_TIMEOUT)

    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=effective_timeout) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
            record_backend_latency(model, latency_ms)
            data = response.json()
            prompt_tokens     = int(data.get("prompt_eval_count", 0) or 0)
            completion_tokens = int(data.get("eval_count", 0) or 0)
            return data.get("response", ""), latency_ms, prompt_tokens, completion_tokens

    except httpx.ReadTimeout:
        latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
        record_backend_timeout(model)
        record_backend_latency(model, latency_ms)
        raise HTTPException(status_code=504, detail="LLM backend timeout")

    except httpx.ConnectError:
        latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
        record_backend_error(model)
        raise HTTPException(status_code=503, detail="LLM backend unreachable")

    except Exception as e:
        latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
        record_backend_error(model)
        raise HTTPException(status_code=502, detail=f"LLM backend error: {type(e).__name__}")
