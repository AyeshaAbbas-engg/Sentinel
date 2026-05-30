import httpx
from fastapi import HTTPException
from config import OLLAMA_URL, OLLAMA_TIMEOUT


async def call_ollama(prompt: str, model: str) -> str:
    """Call Ollama LLM backend. Raises HTTPException on failure (fail-closed)."""
    try:
        async with httpx.AsyncClient(timeout=float(OLLAMA_TIMEOUT)) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False}
            )
            response.raise_for_status()
            return response.json().get("response", "")
    except httpx.ReadTimeout:
        raise HTTPException(status_code=504, detail="LLM backend timeout")
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="LLM backend unreachable")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM backend error: {type(e).__name__}")
