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

## Use — Django

```python
# settings.py
MIDDLEWARE = [
    "defenso.django.DefensoMiddleware",
    # ... rest
]
DEFENSO_TOKEN = os.environ["DEFENSO_TOKEN"]
```

## Use — Flask

```python
from defenso.flask import defenso

app = Flask(__name__)
defenso(app, token=os.environ["DEFENSO_TOKEN"])
```

## Fail-open contract

- Caches the last-known-good policy for 24 hours.
- On Defenso API failure, evaluates against the cached policy.
- On cache miss + API failure, requests pass through and a warning is logged.
- Your app never breaks because Defenso is unreachable.

## Status

Alpha. Scaffold only. Full implementation ships next.
