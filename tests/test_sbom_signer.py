from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from cra_evidence_cli.sbom_signer import (
    SBOMSigningError,
    _decode_sigstore_der_string,
    _extract_signer_identity,
    _extract_signer_issuer,
    sign_sbom_with_sigstore,
)


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
