# BeddrokClient

Python client for the Beddrok API: personnummer in, stable numbers out.

## Installation

```bash
pip install BeddrokClient
```

## Usage

```python
from beddrokclient import BeddrokClient

with BeddrokClient(
    user="cint-clean",
    password="...",
    api_url="http://beddrok-api.rst-vdp-lake-beddrok-prod.svc:8000",
) as beddrok:
    pseudonyms = beddrok.pseudonymize(["199204062355", "920406-2355"])
    pseudonyms["199204062355"].number
    pseudonyms["199204062355"].removed

    resolved = beddrok.resolve([12345])
    resolved[12345].pin
    resolved[12345].status
```

| Method | Endpoint | Access | Returns |
| --- | --- | --- | --- |
| `pseudonymize(pins)` | `POST /pseudonymize` | `encrypt` | `{pin: Pseudonym(pin, number, removed)}` |
| `resolve(numbers)` | `POST /resolve` | `decrypt` | `{number: Resolved(number, pin, status)}`, status `ok`, `removed` or `unknown` |
| `health()` | `GET /health/api` | none | `True` if the API answers |

## What it does for you

- Logs in through `POST /auth/token` and renews the token 5 minutes before it expires, reading the expiry from the JWT. On a 401 it logs in again once and retries.
- Splits input into batches: 1000 pins per `/pseudonymize` call, 20 numbers per `/resolve` call, the API's default limits. Duplicates are sent once.
- Retries connection errors and 503 with exponential backoff, `backoff_base ** attempt` seconds, up to `max_retries`.

## What it never does

- **It never changes a pin.** Pins are sent exactly as given. Beddrok gives `920406-2355` and `199204062355` two different numbers, so pass values exactly as the source has them.
- **It never returns a partial answer.** If any pin or number is missing from the response, it raises `BeddrokError`. It never falls back to the original value.
- **It never puts a personnummer in an error.** `BeddrokError` carries `path`, `status` and the HTTP reason only. Response bodies are never included, because a 422 echoes the request.

## Configuration

```python
BeddrokClient(
    user="...",
    password="...",
    api_url="...",
    timeout=30,
    max_retries=3,
    backoff_base=2.0,
    pseudonymize_batch_size=1000,
    resolve_batch_size=20,
    refresh_token_before_seconds=300,
)
```

## Upgrading from 2.x

3.0 targets the Beddrok API as it is deployed. The 2.x methods called endpoints that API does not have (`/encrypt`, `/decrypt`, `/validate`) and have been removed: `encrypt_pins`, `decrypt_pins`, `validate_pins`, and the pandas and polars DataFrame helpers. Use `pseudonymize` and `resolve` instead. pandas, polars and roskarl are no longer dependencies.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
pyright
pytest
```

The tests run against a local fake Beddrok server, no cluster needed.
