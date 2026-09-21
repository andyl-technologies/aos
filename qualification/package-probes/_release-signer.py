"""Exercises evidence signing with a public, disposable Ed25519 test seed."""

import base64
import json
import pathlib
import subprocess
import sys


def prepare():
    """Creates private fixture files without consulting deployment credentials."""
    root = pathlib.Path.cwd()
    key = root / "fixture.pem"
    # RFC 8410 PKCS#8 wrapper; this published seed is never a release authority.
    der = bytes.fromhex("302e020100300506032b657004220420") + bytes(range(32))
    key.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(der).decode()
        + "\n-----END PRIVATE KEY-----\n"
    )
    key.chmod(0o600)
    config = root / "config.json"
    config.write_text(json.dumps({
        "schema_version": "aos.release.file-signer-config/v1",
        "provider_revision": "qualification-fixture-v1",
        "registries": ["andyl/testing"],
        "keys": [{
            "key_id": "fixture-v1",
            "roles": ["release-evidence"],
            "verification_identity": "fixture-v1",
            "material": {"kind": "ed25519-pkcs8-pem", "private_key": str(key)},
        }],
    }))
    config.chmod(0o600)
    return config


def sign(config):
    return subprocess.run([
        "@out@/bin/aos-release-signer", "--config", str(config),
        "sign-evidence", "--key-id", "fixture-v1", "--payload", "payload.json",
        "--output", "envelope.json",
    ], capture_output=True, text=True)


config = prepare()
payload = pathlib.Path("payload.json")
envelope = pathlib.Path("envelope.json")
if sys.argv[1] == "primary":
    payload.write_text('{"purpose":"package-qualification"}')
    result = sign(config)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    # Independently generated and verified with AOS OpenSSL Ed25519 pkeyutl.
    expected = {
        "schema_version": "aos.hub.signed-release-evidence/v1",
        "key_id": "fixture-v1",
        "payload": {"purpose": "package-qualification"},
        "signature_base64": (
            "r72YlZoRa8O2d6mQ4GP92IW+i1ljYG9p/9Mjnr8YqSRgFwHdjYTKxJi44qC1rl0D"
            "aSTAO5QoeNEOC+MJjtrAAg=="
        ),
    }
    original = envelope.read_bytes()
    assert json.loads(original) == expected
    assert original == json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    assert sign(config).returncode != 0
    assert envelope.read_bytes() == original
    print("Evidence signature and no-overwrite checks passed")
else:
    payload.write_text('{ "purpose": "package-qualification" }')
    result = sign(config)
    assert result.returncode == 1
    assert "canonical" in result.stderr
    assert result.stdout == ""
    assert not envelope.exists()
    sys.stderr.write("Signer rejected noncanonical evidence without output\n")
    raise SystemExit(7)
