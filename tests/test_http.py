import httpx
import pytest
import respx

from pkgwatch.http import HttpError, NotFound, TooLarge

URL = "https://registry.example.test/thing"


@respx.mock
def test_sends_descriptive_user_agent(client, config):
    route = respx.get(URL).respond(json={"ok": True})
    assert client.get_json(URL) == {"ok": True}
    agent = route.calls.last.request.headers["user-agent"]
    assert agent == config.user_agent
    assert agent.startswith("PkgWatch/1.0 (+https://github.com/")


@respx.mock
def test_retries_on_503_then_succeeds_with_backoff(client):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(429), httpx.Response(200, text="ok")]
    )
    assert client.get(URL).body == b"ok"
    assert route.call_count == 3
    assert client.sleeps == [1.0, 2.0]  # exponential backoff


@respx.mock
def test_honours_retry_after_header(client):
    respx.get(URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200)]
    )
    client.get(URL)
    assert client.sleeps == [7.0]


@respx.mock
def test_ignores_unparseable_retry_after(client):
    respx.get(URL).mock(
        side_effect=[httpx.Response(503, headers={"Retry-After": "soon"}), httpx.Response(200)]
    )
    client.get(URL)
    assert client.sleeps == [1.0]


@respx.mock
def test_gives_up_after_max_retries(client, config):
    route = respx.get(URL).respond(502)
    with pytest.raises(HttpError, match="failed after retries"):
        client.get(URL)
    assert route.call_count == config.limits["max_retries"] + 1


@respx.mock
def test_transport_errors_are_retried(client):
    respx.get(URL).mock(side_effect=[httpx.ConnectTimeout("slow"), httpx.Response(200, text="x")])
    assert client.get(URL).body == b"x"


@respx.mock
def test_404_raises_not_found_without_retry(client):
    route = respx.get(URL).respond(404)
    with pytest.raises(NotFound):
        client.get(URL)
    assert route.call_count == 1


@respx.mock
def test_other_4xx_raise_http_error_with_status(client):
    respx.get(URL).respond(403)
    with pytest.raises(HttpError) as info:
        client.get(URL)
    assert info.value.status == 403


@respx.mock
def test_declared_size_over_limit_is_rejected(client):
    respx.get(URL).respond(200, content=b"x" * 50)
    with pytest.raises(TooLarge):
        client.get(URL, max_bytes=10)


@respx.mock
def test_streamed_size_over_limit_is_rejected_without_content_length(client):
    def chunks():
        for _ in range(20):
            yield b"y" * 1000

    respx.get(URL).mock(return_value=httpx.Response(200, content=chunks()))
    with pytest.raises(TooLarge):
        client.get(URL, max_bytes=5000)


@respx.mock
def test_conditional_get_returns_304_with_empty_body(client):
    route = respx.get(URL).respond(304)
    resp = client.get_conditional(URL, "W/abc")
    assert resp.status == 304 and resp.body == b""
    assert route.calls.last.request.headers["if-none-match"] == "W/abc"


@respx.mock
def test_etag_is_exposed_and_token_only_sent_to_github_calls(client):
    route = respx.get(URL).respond(200, headers={"ETag": "v1"})
    assert client.get(URL).etag == "v1"
    assert "authorization" not in route.calls.last.request.headers
    client.get(URL, github=True)
    assert route.calls.last.request.headers["authorization"] == "Bearer test-token"


def test_timeout_is_configured_on_every_request(client, config):
    timeout = client._client.timeout
    assert timeout.connect == timeout.read == config.limits["http_timeout_seconds"]
