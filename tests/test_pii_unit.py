"""Unit coverage for PII span handling without a live Presidio service."""

import asyncio
import os
import sys

_GATEWAY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway"))
if _GATEWAY not in sys.path:
    sys.path.insert(0, _GATEWAY)

# This is a pure scanner unit test; it never contacts the gateway or signs a
# request. Supply only the configuration value required while importing it.
os.environ.setdefault("JWT_SECRET", "unit-test-secret")

from context import RequestContext  # noqa: E402
from scanning import pii  # noqa: E402


class _Response:
    def raise_for_status(self):
        return None

    def json(self):
        return [{"entity_type": "PERSON", "start": 0, "end": 9, "score": 0.99}]


class _Client:
    sent_text = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, _url, json):
        self.__class__.sent_text = json["text"]
        return _Response()


def test_presidio_offsets_are_based_on_original_text(monkeypatch):
    prompt = "Alice Doe email alice@example.com"
    monkeypatch.setattr(pii.httpx, "AsyncClient", lambda **_kwargs: _Client())
    ctx = RequestContext("test", "user", "admin", prompt, prompt)

    result = asyncio.run(pii.scan_pii(ctx))

    assert _Client.sent_text == prompt
    assert result.clean_prompt == "[PERSON] email [EMAIL_ADDRESS]"
