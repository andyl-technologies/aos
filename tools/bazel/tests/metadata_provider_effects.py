"""Compares installed metadata lifecycle and immutable-library authorization."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ACQUISITION = "aos-metadata-acquisition-provider"
POLICY = "aos-metadata-policy-provider"


def invocation(package, command, operation, inputs):
    """Constructs the resolved activation process contract without host effects."""
    return {
        "id": "metadata-qualification", "revision": "revision-one", "action": "apply", "previous": None,
        "input": inputs,
        "effect": {
            "owner": "metadata", "identity": ["qualification", "metadata", operation, "one"],
            "input": inputs, "inputs": {}, "input_type": {"kind": "submodule", "open": True, "fields": {}},
            "after": [], "results": {},
            "handler": {"kind": "process", "artifact": str(package),
                        "executable": str(package / "bin" / command)},
            "dependencies": [], "revision": "revision-one", "lifetime": "instance", "timeout_ms": 10000,
        },
    }


def call(package, command, action, request, rejection=None):
    """Requires canonical successful output or the selected fail-closed diagnostic."""
    result = subprocess.run([str(package / "bin" / command), action],
                            input=json.dumps(request).encode(), capture_output=True, timeout=30)
    if rejection is not None:
        if (result.returncode != 1 or result.stdout
                or not result.stderr.startswith(command.encode() + b":")
                or rejection.encode() not in result.stderr):
            raise ValueError("metadata negative control failed: " + repr(result))
        return {"status": 1, "diagnostic": rejection}
    if result.returncode or result.stderr:
        raise ValueError("installed metadata process failed: " + repr(result))
    value = json.loads(result.stdout)
    # Canonical JSON has sorted keys and no insignificant whitespace.
    if json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() != result.stdout:
        raise ValueError("installed metadata output is not canonical JSON")
    return value


def effects(package, fixtures):
    """Exercises the actual companion in an isolated writable Nix store."""
    completed = {}
    for command, operations in [(ACQUISITION, ["detect", "acquire"]), (POLICY, ["authorize"])]:
        for operation in operations:
            request = invocation(package, command, operation, {})
            assert call(package, command, "observe", request) == {"status": "retry-safe"}
            request["action"] = "remove"
            assert call(package, command, "observe", request) == {"status": "absent"}
            assert call(package, command, "remove", request) == {}
            completed[operation + "-lifecycle"] = "PASS"

        request = invocation(package, command, "unknown", {})
        call(package, command, "observe", request, "unknown metadata")
        request = invocation(package, command, operations[0], {})
        request["action"] = "remove"
        call(package, command, "apply", request, "native action differs from argv")
        completed[command + "-identity-and-action-rejection"] = "PASS"

    host_module = "{ aos.provisioning.storage.partitions = {}; }"
    parameters = {
        "configuration": {
            "schema": "aos.metadata.provisioning-authorization-configuration/v1",
            "trust_mode": "platform", "trusted_config_keys": [],
        },
        "acquired_metadata": {
            "schema": "aos.metadata.acquired-provisioning-input/v1", "platform_id": "qemu",
            "host_module": host_module, "host_module_signature": None, "facts": {},
        },
        "evaluation_context": str(fixtures / "descriptor.json"),
    }
    descriptor = json.loads((fixtures / "descriptor.json").read_text())
    for source, module in [("operator", host_module), ("fallback", None)]:
        parameters["acquired_metadata"]["host_module"] = module
        request = invocation(package, POLICY, "authorize", parameters)
        response = call(package, POLICY, "apply", request)
        authorized = response["authorized_input"]
        assert json.loads(response["canonical_input"]) == authorized
        assert authorized["schema"] == "aos.metadata.authorized-provisioning-input/v1"
        assert authorized["source"] == source and authorized["host_module"] == module
        expected_hash = "sha256:" + hashlib.sha256(module.encode()).hexdigest() if module else None
        assert authorized["host_module_sha256"] == expected_hash
        assert authorized["authorization"] == {"trust_mode": "platform", "platform_id": "qemu", "signer": None}
        assert authorized["base_library"] == {"store_path": descriptor["library"],
                                              "nar_hash": descriptor["libraryNarHash"]}
        completed[source + "-authorization"] = response

    parameters["evaluation_context"] = str(fixtures / "wrong-hash.json")
    request = invocation(package, POLICY, "authorize", parameters)
    completed["wrong-library-nar-rejected"] = call(
        package, POLICY, "apply", request, "native module library NAR differs from its admitted identity")
    parameters["evaluation_context"] = str(fixtures / "descriptor.json")
    request = invocation(package, POLICY, "authorize", parameters)

    # Only package-adjacent tools confer authority; PATH and common helper
    # environment variables cannot rescue a package missing its companion.
    with tempfile.TemporaryDirectory(prefix="metadata-companion-") as temporary:
        relocated = Path(temporary)
        (relocated / "bin").mkdir()
        shutil.copy2(package / "bin" / POLICY, relocated / "bin" / POLICY)
        environment = os.environ.copy()
        try:
            os.environ["PATH"] = str((package / "libexec/nix-store").resolve().parent)
            os.environ["AOS_NIX_STORE"] = str(package / "libexec/nix-store")
            completed["missing-adjacent-companion-rejected"] = call(
                relocated, POLICY, "apply", request, "No such file or directory")
            (relocated / "libexec").mkdir()
            (relocated / "libexec/nix-store").symlink_to((package / "libexec/nix-store").resolve())
            assert call(relocated, POLICY, "apply", request) == completed["fallback-authorization"]
            completed["adjacent-companion-relocation"] = "PASS"
        finally:
            os.environ.clear()
            os.environ.update(environment)
    return completed


def compare(packages, fixtures):
    """Requires equal positive and negative outcomes from both installed packages."""
    reports = {driver: effects(Path(outputs["out"]), fixtures) for driver, outputs in packages.items()}
    if reports["ordinary"] != reports["bazel"]:
        raise ValueError("installed metadata effects differ between build drivers")
    return {"status": "PASS", "cases": reports["ordinary"],
            "limits": ["No cloud network acquisition or privileged host changes are exercised."]}
