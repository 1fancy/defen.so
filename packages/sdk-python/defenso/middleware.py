"""
Starlette / FastAPI-compatible ASGI middleware. Alpha scaffold.

Full implementation TODO:
- policy fetch + 24h cache
- rule evaluation
- background attack-log flush
"""

from __future__ import annotations

import os
from typing import Any


class Defenso:
    def __init__(self, app: Any, token: str | None = None, api_url: str = "https://app.defen.so") -> None:
        self.app = app
        self.token = token or os.environ.get("DEFENSO_TOKEN", "")
        self.api_url = api_url.rstrip("/")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        # TODO: run policy check; on match, short-circuit with 403 and forward attack log.
        # For now pass through (fail-open).
        await self.app(scope, receive, send)
