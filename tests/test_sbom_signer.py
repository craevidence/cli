from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from cra_evidence_cli.sbom_signer import (
    SBOMSigningError,
    _decode_sigstore_der_string,
    _extract_signer_identity,
    _extract_signer_issuer,
    sign_sbom_with_sigstore,
)


def _install_fake_sigstore(monkeypatch):
    from cra_evidence_cli import sbom_signer

    package = ModuleType("sigstore")
    package.__path__ = []
    models = ModuleType("sigstore.models")
    oidc = ModuleType("sigstore.oidc")
    sign = ModuleType("sigstore.sign")

    class ClientTrustConfig:
        @staticmethod
        def production():
            return object()

    class IdentityToken:
        def __init__(self, _token, client_id):
            self.client_id = client_id

    class SigningContext:
        @staticmethod
        def from_trust_config(_config):
            return SigningContext()

        def signer(self, _identity_token):
            return self

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _tb):
            return False

        def sign_artifact(self, input_):
            assert input_ == b"sbom bytes"
            return SimpleNamespace(to_json=lambda: "new signature bundle")

    models.ClientTrustConfig = ClientTrustConfig
    oidc.IdentityToken = IdentityToken
    oidc.detect_credential = lambda _client_id: None
    sign.SigningContext = SigningContext
    monkeypatch.setitem(sys.modules, "sigstore", package)
    monkeypatch.setitem(sys.modules, "sigstore.models", models)
    monkeypatch.setitem(sys.modules, "sigstore.oidc", oidc)
    monkeypatch.setitem(sys.modules, "sigstore.sign", sign)
    monkeypatch.setenv(sbom_signer.SIGSTORE_IDENTITY_TOKEN_ENV, "test-token")
    monkeypatch.setattr(sbom_signer, "_extract_signer_identity", lambda _bundle: "identity")
    monkeypatch.setattr(sbom_signer, "_extract_signer_issuer", lambda _bundle: "issuer")
    monkeypatch.setattr(sbom_signer, "_extract_log_index", lambda _bundle: None)


def test_decode_sigstore_der_string_accepts_plain_and_utf8_der() -> None:
    assert _decode_sigstore_der_string(b"https://issuer.example") == "https://issuer.example"
    assert _decode_sigstore_der_string(b"\x0c\x08identity") == "identity"
    assert _decode_sigstore_der_string(b"\x0c\x81\x08identity") == "identity"


def test_sign_refuses_to_overwrite_existing_bundle(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.json"
    bundle_path = tmp_path / "sbom.json.sigstore.json"
    sbom_path.write_text('{"components": []}', encoding="utf-8")
    bundle_path.write_text("{}", encoding="utf-8")

    with pytest.raises(SBOMSigningError, match="already exists"):
        sign_sbom_with_sigstore(sbom_path=sbom_path, bundle_path=bundle_path)


def test_sign_does_not_overwrite_bundle_created_after_preflight(monkeypatch, tmp_path):
    sbom_path = tmp_path / "sbom.json"
    bundle_path = tmp_path / "sbom.json.sigstore.json"
    sbom_path.write_bytes(b"sbom bytes")
    _install_fake_sigstore(monkeypatch)
    original_open = Path.open

    def create_competing_bundle(path, mode="r", *args, **kwargs):
        if path == bundle_path and mode == "x":
            with original_open(path, "w", encoding="utf-8") as handle:
                handle.write("created while signing")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", create_competing_bundle)

    with pytest.raises(SBOMSigningError, match="already exists"):
        sign_sbom_with_sigstore(sbom_path=sbom_path, bundle_path=bundle_path)

    assert bundle_path.read_text(encoding="utf-8") == "created while signing"


def test_sign_overwrite_option_replaces_existing_bundle(monkeypatch, tmp_path):
    sbom_path = tmp_path / "sbom.json"
    bundle_path = tmp_path / "sbom.json.sigstore.json"
    sbom_path.write_bytes(b"sbom bytes")
    bundle_path.write_text("old bundle", encoding="utf-8")
    _install_fake_sigstore(monkeypatch)

    result = sign_sbom_with_sigstore(
        sbom_path=sbom_path,
        bundle_path=bundle_path,
        overwrite=True,
    )

    assert result.bundle_path == bundle_path
    assert bundle_path.read_text(encoding="utf-8") == "new signature bundle"


def test_sign_output_oserror_is_translated_without_echoing_path(monkeypatch, tmp_path):
    sbom_path = tmp_path / "sbom.json"
    bundle_path = tmp_path / "private" / "bundle.json"
    sbom_path.write_bytes(b"sbom bytes")
    _install_fake_sigstore(monkeypatch)
    original_open = Path.open

    def fail_bundle_open(path, mode="r", *args, **kwargs):
        if path == bundle_path and mode == "x":
            message = "/private/output/marker"
            raise PermissionError(message)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_bundle_open)

    with pytest.raises(SBOMSigningError) as exc_info:
        sign_sbom_with_sigstore(sbom_path=sbom_path, bundle_path=bundle_path)

    assert str(exc_info.value) == "Could not write signature bundle."
    assert "/private/output/marker" not in str(exc_info.value)


def test_extract_signer_identity_prefers_uri_san(monkeypatch) -> None:
    from cryptography.x509 import RFC822Name, UniformResourceIdentifier

    class FakeSAN:
        def get_values_for_type(self, value_type):
            if value_type is UniformResourceIdentifier:
                return [
                    "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main"
                ]
            if value_type is RFC822Name:
                return ["release@example.com"]
            return []

    class FakeExtensions:
        def get_extension_for_class(self, _klass):
            return SimpleNamespace(value=FakeSAN())

    bundle = SimpleNamespace(signing_certificate=SimpleNamespace(extensions=FakeExtensions()))

    assert _extract_signer_identity(bundle) == (
        "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main"
    )


def test_extract_signer_issuer_reads_sigstore_extension() -> None:
    class FakeExtensions:
        def get_extension_for_oid(self, oid):
            if oid.dotted_string != "1.3.6.1.4.1.57264.1.1":
                raise LookupError(oid.dotted_string)
            return SimpleNamespace(
                value=SimpleNamespace(value=b"https://token.actions.githubusercontent.com")
            )

    bundle = SimpleNamespace(signing_certificate=SimpleNamespace(extensions=FakeExtensions()))

    assert _extract_signer_issuer(bundle) == "https://token.actions.githubusercontent.com"
