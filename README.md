# signaldesk-service-kit

Typed, narrow security and HTTP client primitives shared by SignalDesk services.

The package provides strict service-principal/credential models, constant-time
credential verification, a FastAPI dependency for internal service routes, and
bounded `httpx.Timeout` construction. It owns no secrets or persistent state.

```python
from signaldesk_service_kit.auth import build_service_auth_dependency
from signaldesk_service_kit.http import bounded_timeout
```

Python 3.11 is supported. Install with `uv sync` and run tests with
`uv run pytest -q`.
