import base64
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Self
import requests

if TYPE_CHECKING:
    import pyarrow as pa
logger = logging.getLogger(__name__)

TOKEN_LIFETIME_FALLBACK_SECONDS = 30 * 60


class BeddrokError(RuntimeError):
    def __init__(self, *, path: str, status: int | None, reason: str) -> None:
        self.path = path
        self.status = status
        answered = "no response" if status is None else str(status)
        super().__init__(f"Beddrok {path}: {answered} {reason}")


@dataclass(frozen=True)
class Pseudonym:
    pin: str
    number: int
    removed: bool


@dataclass(frozen=True)
class Resolved:
    number: int
    pin: str | None
    status: str


@dataclass
class BeddrokClient:
    user: str
    password: str
    api_url: str
    timeout: float = 30
    max_retries: int = 3
    backoff_base: float = 2.0
    pseudonymize_batch_size: int = 1000
    resolve_batch_size: int = 20
    refresh_token_before_seconds: int = 300
    _session: requests.Session = field(init=False, repr=False)
    _token: str | None = field(default=None, init=False, repr=False)
    _token_renew_at: float = field(default=0.0, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self.api_url = self.api_url.rstrip("/")
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def health(self) -> bool:
        try:
            response = self._session.get(
                f"{self.api_url}/health/api", timeout=self.timeout
            )
        except requests.RequestException:
            return False
        return response.ok

    def pseudonymize(self, pins: list[str]) -> dict[str, Pseudonym]:
        wanted = list(dict.fromkeys(pins))
        result: dict[str, Pseudonym] = {}
        for start in range(0, len(wanted), self.pseudonymize_batch_size):
            batch = wanted[start : start + self.pseudonymize_batch_size]
            body = self._authorized_post(path="/pseudonymize", body={"pins": batch})
            for item in _items(
                path="/pseudonymize", body=body, keys=("pin", "number", "removed")
            ):
                result[item["pin"]] = Pseudonym(
                    pin=item["pin"],
                    number=_integer(path="/pseudonymize", value=item["number"]),
                    removed=bool(item["removed"]),
                )
            missing = len(set(batch) - result.keys())
            if missing:
                raise BeddrokError(
                    path="/pseudonymize",
                    status=200,
                    reason=f"{missing} of {len(batch)} pins got no number",
                )
        return result

    def swap_personnummer_for_numbers(
        self, *, table: "pa.Table", columns: list[str]
    ) -> "pa.Table":
        import pyarrow as pa

        pins = sorted(
            {
                pin
                for column in columns
                for pin in table.column(column).to_pylist()
                if pin is not None
            }
        )
        pseudonyms = self.pseudonymize(pins) if pins else {}
        for column in columns:
            numbers = [
                None if pin is None else pseudonyms[pin].number
                for pin in table.column(column).to_pylist()
            ]
            table = table.set_column(
                table.schema.get_field_index(column),
                pa.field(column, pa.int64()),
                pa.array(numbers, pa.int64()),
            )
        return table

    def resolve(self, numbers: list[int]) -> dict[int, Resolved]:
        wanted = list(dict.fromkeys(numbers))
        result: dict[int, Resolved] = {}
        for start in range(0, len(wanted), self.resolve_batch_size):
            batch = wanted[start : start + self.resolve_batch_size]
            body = self._authorized_post(path="/resolve", body={"numbers": batch})
            for item in _items(
                path="/resolve", body=body, keys=("number", "pin", "status")
            ):
                number = _integer(path="/resolve", value=item["number"])
                result[number] = Resolved(
                    number=number, pin=item["pin"], status=str(item["status"])
                )
            missing = len(set(batch) - result.keys())
            if missing:
                raise BeddrokError(
                    path="/resolve",
                    status=200,
                    reason=f"{missing} of {len(batch)} numbers got no answer",
                )
        return result

    def _send(
        self,
        *,
        path: str,
        headers: dict[str, str],
        json_body: Any = None,
        form_body: dict[str, str] | None = None,
    ) -> requests.Response:
        attempt = 1
        while True:
            try:
                response = self._session.post(
                    f"{self.api_url}{path}",
                    json=json_body,
                    data=form_body,
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as error:
                if attempt >= self.max_retries:
                    raise BeddrokError(
                        path=path, status=None, reason=type(error).__name__
                    ) from None
            else:
                if response.status_code != 503:
                    return response
                if attempt >= self.max_retries:
                    raise BeddrokError(
                        path=path, status=503, reason="database unavailable"
                    )
            wait = self.backoff_base**attempt
            logger.warning(
                "Beddrok %s attempt %d of %d failed, retrying in %.0fs",
                path,
                attempt,
                self.max_retries,
                wait,
            )
            time.sleep(wait)
            attempt += 1

    def _json(self, *, path: str, response: requests.Response) -> Any:
        if not response.ok:
            raise BeddrokError(
                path=path, status=response.status_code, reason=response.reason
            )
        try:
            return response.json()
        except ValueError:
            raise BeddrokError(
                path=path, status=response.status_code, reason="response is not JSON"
            ) from None

    def _login(self) -> None:
        path = "/auth/token"
        response = self._send(
            path=path,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            form_body={
                "grant_type": "password",
                "username": self.user,
                "password": self.password,
            },
        )
        body = self._json(path=path, response=response)
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str):
            raise BeddrokError(
                path=path,
                status=response.status_code,
                reason="no access_token in response",
            )
        self._token = token
        self._token_renew_at = (
            _token_expiry(token=token) - self.refresh_token_before_seconds
        )

    def _bearer(self, *, force_login: bool = False) -> str:
        with self._lock:
            if (
                force_login
                or self._token is None
                or time.time() >= self._token_renew_at
            ):
                self._login()
            return f"Bearer {self._token}"

    def _authorized_post(self, *, path: str, body: dict[str, Any]) -> Any:
        headers = {"Content-Type": "application/json", "Authorization": self._bearer()}
        response = self._send(path=path, headers=headers, json_body=body)
        if response.status_code == 401:
            headers["Authorization"] = self._bearer(force_login=True)
            response = self._send(path=path, headers=headers, json_body=body)
        return self._json(path=path, response=response)


def _token_expiry(*, token: str) -> float:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except (IndexError, KeyError, ValueError, TypeError):
        return time.time() + TOKEN_LIFETIME_FALLBACK_SECONDS


def _items(*, path: str, body: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if not isinstance(body, list) or not all(
        isinstance(item, dict) and set(keys) <= item.keys() for item in body
    ):
        raise BeddrokError(
            path=path,
            status=200,
            reason=f"expected a list of objects with {', '.join(keys)}",
        )
    return body


def _integer(*, path: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BeddrokError(
            path=path, status=200, reason=f"number is {type(value).__name__}, not int"
        )
    return value
