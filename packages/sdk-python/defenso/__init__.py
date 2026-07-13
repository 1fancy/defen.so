"""
Defenso Python SDK — fail-open security middleware.

Wire it into your framework of choice. Talks to https://app.defen.so/api/policy
for rule sync and https://app.defen.so/api/attacks/ingest for attack telemetry.
Never blocks a request when Defenso is unreachable.
"""

__version__ = "0.1.0"

from .middleware import Defenso  # re-export for FastAPI: app.add_middleware(Defenso, ...)

__all__ = ["Defenso", "__version__"]
