import base64
import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

import pytest

from beddrokclient import BeddrokClient, BeddrokError, Pseudonym

SECRET = "199204062355"


def jwt(*, exp: float) -> str:
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    )
    return f"header.{payload}.signature"


class FakeBeddrok:
    def __init__(self) -> None:
        self.numbers: dict[str, int] = {}
        self.removed: set[str] = set()
        self.tokens: set[str] = set()
        self.logins = 0
        self.batches: list[int] = []
        self.max_pins = 1000
        self.token_exp = time.time() + 1800
        self.fail_with: list[int] = []
        self.drop_pins: set[str] = set()
        self.answer_override: Any = None
        self.url = ""

    def serve(self) -> ThreadingHTTPServer:
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def reply(self, code: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                self.reply(200 if self.path == "/health/api" else 404, {"status": "ok"})

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if api.fail_with:
                    return self.reply(api.fail_with.pop(0), {"detail": "fail"})
                if self.path == "/auth/token":
                    form = parse_qs(body.decode())
                    if form.get("username") != ["cint"] or form.get("password") != [
                        "pw"
                    ]:
                        return self.reply(
                            401, {"detail": "Incorrect username or password"}
                        )
                    if form.get("grant_type") != ["password"]:
                        return self.reply(422, {"detail": "grant_type"})
                    api.logins += 1
                    token = jwt(exp=api.token_exp + api.logins)
                    api.tokens.add(token)
                    return self.reply(
                        200, {"access_token": token, "token_type": "bearer"}
                    )
                if (
                    self.headers.get("Authorization", "").removeprefix("Bearer ")
                    not in api.tokens
                ):
                    return self.reply(401, {"detail": "Not authenticated"})
                if self.path == "/pseudonymize":
                    pins = json.loads(body)["pins"]
                    if len(pins) > api.max_pins:
                        return self.reply(
                            422, {"detail": [{"msg": "too many pins", "input": pins}]}
                        )
                    api.batches.append(len(pins))
                    if api.answer_override is not None:
                        return self.reply(200, api.answer_override)
                    out = []
                    for pin in pins:
                        if pin in api.drop_pins:
                            continue
                        api.numbers.setdefault(pin, len(api.numbers) + 1)
                        out.append(
                            {
                                "pin": pin,
                                "number": api.numbers[pin],
                                "removed": pin in api.removed,
                            }
                        )
                    return self.reply(200, out)
                if self.path == "/resolve":
                    by_number = {n: p for p, n in api.numbers.items()}
                    out = []
                    for number in json.loads(body)["numbers"]:
                        pin = by_number.get(number)
                        status = (
                            "unknown"
                            if pin is None
                            else "removed"
                            if pin in api.removed
                            else "ok"
                        )
                        out.append(
                            {
                                "number": number,
                                "pin": pin if status == "ok" else None,
                                "status": status,
                            }
                        )
                    return self.reply(200, out)
                self.reply(404, {"detail": "Not Found"})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        return server


@pytest.fixture
def api() -> Iterator[FakeBeddrok]:
    fake = FakeBeddrok()
    server = fake.serve()
    yield fake
    server.shutdown()


def client(api: FakeBeddrok, **kwargs: Any) -> BeddrokClient:
    return BeddrokClient(
        user="cint", password="pw", api_url=api.url, backoff_base=0.01, **kwargs
    )


def test_pseudonymize_returns_number_and_removed(api: FakeBeddrok) -> None:
    api.removed.add("191212121212")
    result = client(api).pseudonymize(["191212121212", SECRET])
    assert result["191212121212"] == Pseudonym(
        pin="191212121212", number=1, removed=True
    )
    assert result[SECRET] == Pseudonym(pin=SECRET, number=2, removed=False)


def test_same_pin_same_number_and_spelling_matters(api: FakeBeddrok) -> None:
    c = client(api)
    first = c.pseudonymize([SECRET, "920406-2355"])
    second = c.pseudonymize([SECRET])
    assert first[SECRET].number == second[SECRET].number
    assert first[SECRET].number != first["920406-2355"].number


def test_batches_and_dedupes(api: FakeBeddrok) -> None:
    pins = [f"19800101{i:04d}" for i in range(2500)]
    result = client(api).pseudonymize(pins + pins[:10])
    assert len(result) == 2500
    assert api.batches == [1000, 1000, 500]


def test_logs_in_once_and_renews_near_expiry(api: FakeBeddrok) -> None:
    c = client(api)
    c.pseudonymize(["1"])
    c.pseudonymize(["2"])
    assert api.logins == 1
    api.token_exp = time.time() + 60
    api.tokens.clear()
    c.pseudonymize(["3"])
    c.pseudonymize(["4"])
    assert api.logins == 3


def test_relogs_once_on_401(api: FakeBeddrok) -> None:
    c = client(api)
    c.pseudonymize(["1"])
    api.tokens.clear()
    c.pseudonymize(["2"])
    assert api.logins == 2


def test_missing_pin_raises_instead_of_keeping_it(api: FakeBeddrok) -> None:
    api.drop_pins.add(SECRET)
    with pytest.raises(BeddrokError, match="1 of 2 pins got no number") as error:
        client(api).pseudonymize(["191212121212", SECRET])
    assert SECRET not in str(error.value)


def test_errors_never_carry_pins(api: FakeBeddrok) -> None:
    with pytest.raises(BeddrokError) as error:
        client(api, pseudonymize_batch_size=5000).pseudonymize(
            [SECRET] + [f"x{i}" for i in range(1000)]
        )
    assert error.value.status == 422
    assert SECRET not in str(error.value)
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_bad_login(api: FakeBeddrok) -> None:
    with pytest.raises(BeddrokError) as error:
        BeddrokClient(user="cint", password="nope", api_url=api.url).pseudonymize(["1"])
    assert error.value.status == 401 and error.value.path == "/auth/token"


def test_retries_503_then_succeeds(api: FakeBeddrok) -> None:
    c = client(api)
    c.pseudonymize(["1"])
    api.fail_with = [503, 503]
    assert c.pseudonymize(["2"])["2"].number == 2


def test_gives_up_after_max_retries(api: FakeBeddrok) -> None:
    c = client(api)
    c.pseudonymize(["1"])
    api.fail_with = [503, 503, 503]
    with pytest.raises(BeddrokError, match="503 database unavailable"):
        c.pseudonymize(["2"])


def test_unreachable() -> None:
    with pytest.raises(BeddrokError, match="no response"):
        BeddrokClient(
            user="u",
            password="p",
            api_url="http://127.0.0.1:9",
            backoff_base=0.01,
            timeout=1,
        ).pseudonymize(["1"])


@pytest.mark.parametrize(
    "answer",
    [
        {"results": []},
        [{"pin": "1", "number": "1", "removed": False}],
        [{"pin": "1", "number": True, "removed": False}],
        [{"pin": "1"}],
    ],
)
def test_rejects_unexpected_shapes(api: FakeBeddrok, answer: Any) -> None:
    api.answer_override = answer
    with pytest.raises(BeddrokError):
        client(api).pseudonymize(["1"])


def test_resolve(api: FakeBeddrok) -> None:
    c = client(api)
    numbers = c.pseudonymize(["191212121212", SECRET])
    api.removed.add(SECRET)
    resolved = c.resolve([numbers["191212121212"].number, numbers[SECRET].number, 999])
    assert resolved[numbers["191212121212"].number].pin == "191212121212"
    assert (
        resolved[numbers[SECRET].number].status == "removed"
        and resolved[numbers[SECRET].number].pin is None
    )
    assert resolved[999].status == "unknown"


def test_health(api: FakeBeddrok) -> None:
    assert client(api).health()
    assert not BeddrokClient(
        user="u", password="p", api_url="http://127.0.0.1:9", timeout=1
    ).health()


def test_empty_input_makes_no_calls(api: FakeBeddrok) -> None:
    assert client(api).pseudonymize([]) == {}
    assert api.logins == 0


def test_swap_personnummer_for_numbers(api: FakeBeddrok) -> None:
    import pyarrow as pa

    table = pa.table(
        {
            "id": [1, 2, 3],
            "patient": [SECRET, "191212121212", None],
            "relative": ["191212121212", None, SECRET],
        }
    )
    swapped = client(api).swap_personnummer_for_numbers(
        table=table, columns=["patient", "relative"]
    )
    numbers = api.numbers
    assert swapped.schema.field("patient").type == pa.int64()
    assert swapped.column("patient").to_pylist() == [
        numbers[SECRET],
        numbers["191212121212"],
        None,
    ]
    assert swapped.column("relative").to_pylist() == [
        numbers["191212121212"],
        None,
        numbers[SECRET],
    ]
    assert swapped.column("id").to_pylist() == [1, 2, 3]
    assert api.batches == [2]


def test_swap_with_only_nulls_makes_no_calls(api: FakeBeddrok) -> None:
    import pyarrow as pa

    table = pa.table({"patient": pa.array([None, None], pa.string())})
    swapped = client(api).swap_personnummer_for_numbers(
        table=table, columns=["patient"]
    )
    assert swapped.column("patient").to_pylist() == [None, None]
    assert api.logins == 0
