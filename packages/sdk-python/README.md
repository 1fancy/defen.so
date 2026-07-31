# defenso (Python)

Fail-open Defenso middleware for Python web apps.

## Install

```bash
pip install defenso
```

## Use — FastAPI

```python
from fastapi import FastAPI
from defenso import Defenso

app = FastAPI()
app.add_middleware(Defenso, token=os.environ["DEFENSO_TOKEN"])
```

Only the ASGI middleware (FastAPI / Starlette) ships today. Django and Flask
adapters are coming soon — there is no `defenso.django` or `defenso.flask`
module yet, so don't import them.

## Status

Scaffold — this SDK currently passes every request through and does not yet
inspect, block, cache policy, or forward attack logs. For working protection
today use the CNAME edge (point your domain at guard.defen.so — full WAF, no
code) or the Node/PHP SDKs.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-python)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
