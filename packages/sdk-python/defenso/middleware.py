"""
Defenso Python SDK — Starlette / FastAPI-compatible ASGI middleware.

Design principles (mirror the Node & PHP SDKs):
- **Fails open.** If Defenso is unreachable or slow, the request is allowed.
  No user-facing latency, no outage propagation.
- **Policy is cached.** WAF rules are pulled in the background and evaluated
  locally; the request path never blocks on a network call.
- **Logs are fire-and-forget.** Attack events are queued and flushed on a
  background thread; queueing never blocks the response.
"""

from __future__ import annotations

import os
import re
import time
import json
import threading
from typing import Any, Optional
from urllib import request as _urlrequest
from urllib.error import URLError


class _Policy:
    """Cached, locally-evaluated WAF policy."""

    def __init__(self) -> None:
        self.version: str = ""
        self.rules: list[dict[str, Any]] = []
        self.updated_at: float = 0.0

    def replace(self, raw: dict[str, Any]) -> None:
        compiled: list[dict[str, Any]] = []
        for r in raw.get("rules", []):
            try:
                flags = re.IGNORECASE if "i" in (r.get("flags") or "") else 0
                compiled.append(
                    {
                        "id": r.get("id"),
                        "pattern": re.compile(r.get("pattern", ""), flags),
                        "target": r.get("target", "query"),
                        "action": r.get("action", "block"),
                        "category": r.get("category", ""),
                    }
                )
            except re.error:
                # A malformed rule is skipped, never fatal — fail open.
                continue
        self.rules = compiled
        self.version = str(raw.get("version", ""))
        self.updated_at = time.time()


class Defenso:
    """
    ASGI middleware.

        app.add_middleware(Defenso, token=os.environ["DEFENSO_TOKEN"])
    """

    def __init__(
        self,
        app: Any,
        token: Optional[str] = None,
        api_url: str = "https://app.defen.so/api",
        policy_refresh_seconds: float = 300.0,
        policy_timeout_seconds: float = 1.0,
    ) -> None:
        self.app = app
        self.token = token or os.environ.get("DEFENSO_TOKEN", "")
        self.api_url = api_url.rstrip("/")
        self.policy_refresh_seconds = policy_refresh_seconds
        self.policy_timeout_seconds = policy_timeout_seconds
        self._policy = _Policy()
        self._log_queue: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        # Prime the policy in a daemon thread so import/startup never blocks.
        if self.token:
            threading.Thread(target=self._refresh_loop, daemon=True).start()

    # ── policy refresh (background, off the request path) ──────────────
    def _refresh_loop(self) -> None:
        while True:
            self._refresh_once()
            time.sleep(self.policy_refresh_seconds)

    def _refresh_once(self) -> None:
        try:
            req = _urlrequest.Request(
                f"{self.api_url}/policy",
                headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            )
            with _urlrequest.urlopen(req, timeout=self.policy_timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self._policy.replace(data)
        except (URLError, ValueError, TimeoutError, OSError):
            # Fail open: keep the last-known-good policy (or none). Never raise.
            pass

    # ── request evaluation (local, no network) ─────────────────────────
    def _evaluate(self, method: str, path: str, query: str, headers: dict[str, str]) -> Optional[dict[str, Any]]:
        targets = {
            "url": path,
            "query": query,
            "headers": " ".join(f"{k}:{v}" for k, v in headers.items()),
        }
        for rule in self._policy.rules:
            hay = targets.get(rule["target"], query)
            if hay and rule["pattern"].search(hay):
                return rule
        return None

    def _queue_log(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._log_queue.append(entry)
            batch = None
            if len(self._log_queue) >= 25:
                batch, self._log_queue = self._log_queue, []
        if batch:
            threading.Thread(target=self._flush, args=(batch,), daemon=True).start()

    def _flush(self, batch: list[dict[str, Any]]) -> None:
        try:
            body = json.dumps({"logs": batch}).encode("utf-8")
            req = _urlrequest.Request(
                f"{self.api_url}/attacks/ingest",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            _urlrequest.urlopen(req, timeout=self.policy_timeout_seconds).close()
        except Exception:
            # Logs are best-effort — dropping them must never affect traffic.
            pass

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        if scope.get("type") != "http" or not self.token:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")
        query = (scope.get("query_string", b"") or b"").decode("latin-1")
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        try:
            match = self._evaluate(method, path, query, headers)
        except Exception:
            match = None  # any evaluation error → fail open

        if match and match["action"] == "block":
            ip = headers.get("cf-connecting-ip") or headers.get("x-forwarded-for", "").split(",")[0].strip()
            self._queue_log(
                {
                    "at": int(time.time()),
                    "verdict": {"action": "block", "rule": {"id": match["id"]}, "reason": match["category"]},
                    "request": {"method": method, "url": f"{path}?{query}", "ip": ip or None},
                }
            )
            payload = json.dumps(
                {"error": "Request blocked by Defenso", "rule": match["id"]}
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return

        # allow / challenge fall through — the app serves normally.
        await self.app(scope, receive, send)
