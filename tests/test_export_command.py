"""The export command while the server is still preparing the file."""

import json

import pytest
from click.testing import CliRunner
from httpx import Response

from cra_evidence_cli.cli import cli as root
from cra_evidence_cli.commands.export import _waited


def _serve(monkeypatch, responses):
    class FakeAsyncClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, method, url, headers=None, **kwargs):
            return responses.pop(0)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setattr("cra_evidence_cli.client.asyncio.sleep", no_sleep)
    monkeypatch.setenv("CRA_EVIDENCE_API_KEY", "test_key_12345")
    monkeypatch.setenv("CRA_EVIDENCE_URL", "https://api.test.craevidence.com")
    monkeypatch.setenv("CRA_NO_WARN", "1")


def _preparing():
    return Response(
        status_code=503,
        headers={"Retry-After": "60"},
        json={"error": {"message": "Still being prepared."}},
    )


def test_progress_goes_to_stderr_and_json_stays_parseable(monkeypatch, tmp_path):
    """A pipeline must see the wait is alive, and parsing stdout must still work."""
    _serve(monkeypatch, [_preparing() for _ in range(6)] + [Response(200, content=b"zip")])
    out = tmp_path / "bundle.zip"

    result = CliRunner().invoke(
        root,
        ["--output", "json", "export", "--product", "p", "--version", "1.0", "--output", str(out)],
    )

    assert result.exit_code == 0, result.output
    assert out.read_bytes() == b"zip"
    assert json.loads(result.stdout)["status"] == "success"
    assert result.stderr.count("Still preparing the technical-file") == 6


def test_a_wait_of_zero_stops_after_the_usual_retries(monkeypatch, tmp_path):
    """Someone who sets the limit to 0 does not get a long wait, and the command fails."""
    _serve(monkeypatch, [_preparing() for _ in range(4)])
    monkeypatch.setenv("CRA_EVIDENCE_EXPORT_WAIT", "0")

    out = tmp_path / "b.zip"

    result = CliRunner().invoke(
        root,
        ["export", "--product", "p", "--version", "1.0", "--output", str(out)],
    )

    assert result.exit_code != 0
    assert not out.exists()
    assert "Still being prepared" in result.output
    assert "Still preparing" not in result.stderr


@pytest.mark.parametrize(
    ("seconds", "expected"), [(9, "9s"), (60, "1m 0s"), (190.4, "3m 10s")]
)
def test_the_wait_reads_in_minutes(seconds, expected):
    assert _waited(seconds) == expected
