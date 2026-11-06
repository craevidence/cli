"""Tests for API key masking, client headers, and GET retry behavior."""


import pytest
from httpx import Response

from cra_evidence_cli.client import CRAEvidenceClient, mask_api_key
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import APIError


class TestMaskApiKey:
    """Tests for API key masking."""

    def test_normal_key(self):
        """Keys longer than 8 chars are masked to first4****last4."""
        assert mask_api_key("cra_abcdef123456") == "cra_****3456"

    def test_short_key(self):
        """Keys of 8 chars or fewer are fully replaced with '****'."""
        assert mask_api_key("short") == "****"
        assert mask_api_key("12345678") == "****"

    def test_empty_key(self):
        """Empty string returns '****'."""
        assert mask_api_key("") == "****"

    def test_nine_char_key(self):
        """9-char key is partially masked (first 4 and last 4 preserved)."""
        result = mask_api_key("123456789")
        assert result == "1234****6789"

    def test_cra_prefix_preserved(self):
        """'cra_' prefix remains visible and '****' follows immediately."""
        result = mask_api_key("cra_key_abc123def456")
        assert result.startswith("cra_")
        assert "****" in result


class TestClientInit:
    """Tests for client initialization."""

    def test_headers_include_cli_version(self):
        """X-CLI-Version header is present and non-empty."""
        config = CRAEvidenceConfig(
            api_key="test_key_12345",
            url="https://api.test.craevidence.com",
        )
        client = CRAEvidenceClient(config)
        headers = client._get_headers()
        assert "X-CLI-Version" in headers
        assert headers["X-CLI-Version"]  # Not empty


class TestRequestWithRetry:
    """Retry behavior of _request_with_retry: retry on 429/5xx with
    exponential backoff, honour Retry-After, and cap the wait at 60s."""

    URL = "https://api.test.craevidence.com/api/v1/ci/status"

    def _client(self):
        config = CRAEvidenceConfig(
            api_key="test_key_12345",
            url="https://api.test.craevidence.com",
        )
        return CRAEvidenceClient(config)

    def _patch_transport(self, monkeypatch, responses):
        """Replace httpx.AsyncClient and asyncio.sleep; return call records."""
        requests: list[tuple[str, str, dict]] = []
        sleeps: list[float] = []

        class FakeAsyncClient:
            def __init__(self, timeout=None, **_kwargs):
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def request(self, method, url, headers=None, **kwargs):
                requests.append((method, url, headers))
                return responses.pop(0)

        async def fake_sleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(
            "cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient
        )
        monkeypatch.setattr("cra_evidence_cli.client.asyncio.sleep", fake_sleep)
        return requests, sleeps

    @pytest.mark.asyncio
    async def test_keeps_waiting_while_the_server_is_still_preparing(self, monkeypatch):
        """A slow export answers 503 with Retry-After many times; four attempts must
        not be the limit when the caller agreed to wait."""
        waiting = [
            Response(status_code=503, headers={"Retry-After": "60"}) for _ in range(9)
        ]
        requests, sleeps = self._patch_transport(
            monkeypatch, [*waiting, Response(status_code=200, content=b"zip")]
        )

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=1200
        )

        assert response.status_code == 200
        assert len(requests) == 10
        assert sleeps == [60.0] * 9

    def _patch_clock(self, monkeypatch, request_seconds=0.0):
        """Time passes only through sleeps and requests; returns the request start times."""
        clock = {"now": 1000.0}
        starts: list[float] = []

        class FakeAsyncClient:
            def __init__(self, timeout=None, **_kwargs):
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def request(self, method, url, headers=None, **kwargs):
                starts.append(clock["now"] - 1000.0)
                clock["now"] += request_seconds
                return Response(status_code=503, headers={"Retry-After": "60"})

        async def fake_sleep(seconds):
            clock["now"] += seconds

        monkeypatch.setattr(
            "cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient
        )
        monkeypatch.setattr("cra_evidence_cli.client.asyncio.sleep", fake_sleep)
        monkeypatch.setattr(
            "cra_evidence_cli.client.time.monotonic", lambda: clock["now"]
        )
        return starts

    @pytest.mark.asyncio
    async def test_a_limit_shorter_than_retry_after_is_kept(self, monkeypatch):
        """Ordinary retries must not outlive the limit: one second must not become
        three minutes of 60 second sleeps."""
        starts = self._patch_clock(monkeypatch)

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=1
        )

        assert response.status_code == 503
        assert starts == [0.0, 1.0]

    @pytest.mark.asyncio
    async def test_a_positive_limit_ends_the_wait(self, monkeypatch):
        """A server that never finishes stops the wait at the limit, not one sleep past it."""
        starts = self._patch_clock(monkeypatch)

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=150
        )

        assert response.status_code == 503
        assert starts == [0.0, 60.0, 120.0, 150.0]

    @pytest.mark.asyncio
    async def test_slow_requests_count_against_the_limit(self, monkeypatch):
        """Request time is part of the wait, and no request starts after the limit."""
        starts = self._patch_clock(monkeypatch, request_seconds=30.0)

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=100
        )

        assert response.status_code == 503
        assert starts == [0.0, 90.0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("-1", [1.0, 2.0, 4.0]),
            ("NaN", [1.0, 2.0, 4.0]),
            ("inf", [1.0, 2.0, 4.0]),
            ("Wed, 21 Oct 2026 07:28:00 GMT", [1.0, 2.0, 4.0]),
            ("0", [0.0, 0.0, 0.0]),
            ("90", [60.0, 60.0, 60.0]),
        ],
    )
    async def test_retry_after_values(self, monkeypatch, value, expected):
        """An unusable value falls back to the usual backoff instead of a rapid loop or a
        crash; a usable one is honoured and capped."""
        _requests, sleeps = self._patch_transport(
            monkeypatch,
            [Response(status_code=503, headers={"Retry-After": value}) for _ in range(4)],
        )

        response = await self._client()._request_with_retry("GET", self.URL)

        assert response.status_code == 503
        assert sleeps == expected

    @pytest.mark.asyncio
    async def test_a_zero_retry_after_does_not_poll_rapidly_while_waiting(self, monkeypatch):
        """Zero is honoured for ordinary retries, but during the long wait it would
        mean hammering the server for the whole limit."""
        _requests, sleeps = self._patch_transport(
            monkeypatch,
            [
                *[Response(status_code=503, headers={"Retry-After": "0"}) for _ in range(5)],
                Response(status_code=200, content=b"zip"),
            ],
        )

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=1200
        )

        assert response.status_code == 200
        assert sleeps == [1.0] * 5

    @pytest.mark.asyncio
    async def test_gives_up_when_the_wait_is_over(self, monkeypatch):
        """A server that never finishes must not hold a pipeline forever."""
        requests, _sleeps = self._patch_transport(
            monkeypatch,
            [Response(status_code=503, headers={"Retry-After": "60"}) for _ in range(5)],
        )

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=0
        )

        assert response.status_code == 503
        assert len(requests) == 4

    @pytest.mark.asyncio
    async def test_a_real_failure_is_not_waited_for(self, monkeypatch):
        """Only a 503 with Retry-After means still preparing: other failures stop at
        the normal attempts even when the caller agreed to wait."""
        requests, _sleeps = self._patch_transport(
            monkeypatch,
            [Response(status_code=500) for _ in range(5)],
        )

        response = await self._client()._request_with_retry(
            "GET", self.URL, wait_for_ready_seconds=1200
        )

        assert response.status_code == 500
        assert len(requests) == 4

    @pytest.mark.asyncio
    async def test_429_then_success_retries_once(self, monkeypatch):
        """A 429 is retried after the first backoff step and the following
        200 is returned."""
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [Response(status_code=429), Response(status_code=200, json={"ok": True})],
        )
        client = self._client()

        response = await client._request_with_retry("GET", self.URL)

        assert response.status_code == 200
        assert response.json() == {"ok": True}
        assert len(requests) == 2
        assert sleeps == [1.0]

    @pytest.mark.asyncio
    async def test_redirect_is_rejected_without_retry(self, monkeypatch):
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [
                Response(
                    status_code=307,
                    headers={"Location": "https://other.example/api/v1/ci/status"},
                )
            ],
        )
        client = self._client()

        with pytest.raises(APIError, match="Authenticated redirects are not followed"):
            await client._request_with_retry("GET", self.URL)

        assert len(requests) == 1
        assert sleeps == []

    @pytest.mark.asyncio
    async def test_5xx_exhaustion_returns_last_response(self, monkeypatch):
        """Persistent 5xx exhausts all retries (4 attempts, backoff 1/2/4s)
        and the last response is returned for error handling."""
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [Response(status_code=500) for _ in range(4)],
        )
        client = self._client()

        response = await client._request_with_retry("GET", self.URL)

        assert response.status_code == 500
        assert len(requests) == 4
        assert sleeps == [1.0, 2.0, 4.0]

    @pytest.mark.asyncio
    async def test_retry_after_header_is_honored(self, monkeypatch):
        """A parseable Retry-After header overrides the backoff step."""
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [
                Response(status_code=429, headers={"Retry-After": "7"}),
                Response(status_code=200, json={}),
            ],
        )
        client = self._client()

        response = await client._request_with_retry("GET", self.URL)

        assert response.status_code == 200
        assert len(requests) == 2
        assert sleeps == [7.0]

    @pytest.mark.asyncio
    async def test_retry_after_is_capped_at_60_seconds(self, monkeypatch):
        """An excessive Retry-After header never sleeps longer than 60s."""
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [
                Response(status_code=429, headers={"Retry-After": "3600"}),
                Response(status_code=200, json={}),
            ],
        )
        client = self._client()

        response = await client._request_with_retry("GET", self.URL)

        assert response.status_code == 200
        assert sleeps == [60.0]

    @pytest.mark.asyncio
    async def test_unparseable_retry_after_falls_back_to_backoff(self, monkeypatch):
        """A non-numeric Retry-After header falls back to the backoff step."""
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [
                Response(status_code=429, headers={"Retry-After": "soon"}),
                Response(status_code=200, json={}),
            ],
        )
        client = self._client()

        response = await client._request_with_retry("GET", self.URL)

        assert response.status_code == 200
        assert sleeps == [1.0]

    @pytest.mark.asyncio
    async def test_non_retryable_4xx_is_returned_immediately(self, monkeypatch):
        """A 404 is not retried and no sleep happens."""
        requests, sleeps = self._patch_transport(
            monkeypatch,
            [Response(status_code=404, json={"detail": "not found"})],
        )
        client = self._client()

        response = await client._request_with_retry("GET", self.URL)

        assert response.status_code == 404
        assert len(requests) == 1
        assert sleeps == []

    @pytest.mark.asyncio
    async def test_request_carries_auth_headers(self, monkeypatch):
        """Headers built inside the retry helper include the bearer key."""
        requests, _ = self._patch_transport(
            monkeypatch,
            [Response(status_code=200, json={})],
        )
        client = self._client()

        await client._request_with_retry("GET", self.URL)

        method, url, headers = requests[0]
        assert method == "GET"
        assert url == self.URL
        assert headers["Authorization"] == "Bearer test_key_12345"
