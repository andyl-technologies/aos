"""Derive a structural profile pin from an explicitly measured runtime preflight.

The existing Rust reviewer prepares an unsigned candidate from authenticated
discovery and independently selected current measurements. Neither preparation
nor the structural digest authorizes an installation. Final qualification runs
again after the final Copy/List bindings and process have been installed.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def check_runtime_profile_selection(selection, identity, measured):
    """Require the actual preflight audience and both selected original documents."""
    actual = identity["identity"]
    for name in ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion"):
        if selection[name] != actual[name]:
            raise ValueError("Runtime preflight selection changes the actual discovery audience")
    if (selection["executionKind"] != "emulated_external"
            or selection["documents"]["deploymentIdentity"]["sha256"] != identity["identitySha256"]
            or selection["documents"]["installation"]["sha256"] != measured["installationSha256"]):
        raise ValueError("Runtime preflight selection replaces current discovery or installation")


def prepare_current_runtime_profile(tools, identity, measured, observation_hashes, label):
    """Run source-owned candidate preparation and the canonical structural projector."""
    if re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label) is None:
        raise ValueError("Runtime preflight retention label differs")
    reviewed = await_direct_review(label + "-runtime-preflight", observation_hashes, {"runtimeSelection"})
    reference = reviewed["selection"]["runtimeSelection"]
    raw = direct_selected_bytes(reference, 262144)
    selected = _closed_review_json(raw)
    check_runtime_profile_selection(selected, identity, measured)
    root = Path("external-direct-flow").resolve()
    candidate_file = root / (label + "-unsigned-runtime-candidate.json")
    arguments = [tools["reviewer"], "prepare", "--selection-file", reference["path"],
        "--output", str(candidate_file)]
    receipt = _run_profile_projection(arguments, label + "-runtime-prepare")
    candidate = _closed_review_json(candidate_file.read_bytes())
    if candidate["selectionSha256"] != reference["sha256"]:
        raise ValueError("Rust candidate preparation consumed a different selection")
    artifact = candidate["artifact"]
    actual = identity["identity"]
    if any(artifact[name] != actual[name] for name in
           ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion")):
        raise ValueError("Rust candidate preparation changed the actual audience")
    profiles = artifact["evidence"]["externalProfiles"]
    if len(profiles) != 1 or profiles[0]["runtimeQualification"] != artifact["evidence"]["runtime"]:
        raise ValueError("Runtime preflight must retain its one actual protected profile")
    wrapper = json.dumps(profiles[0], separators=(",", ":")).encode()
    wrapper_name = label + "-runtime-profile.json"
    wrapper_sha = retain_direct_flow(wrapper_name, wrapper)
    wrapper_file = root / wrapper_name
    projected = _run_profile_projection([tools["providerConformance"], "profile-digest",
        "--profile-file", str(wrapper_file)], label + "-profile-digest")
    value = _closed_review_json(projected["stdout"])
    if (set(value) != {"version", "profile_sha256", "protected_profile_digest"}
            or value["version"] != 1 or value["profile_sha256"] != wrapper_sha
            or re.fullmatch(r"[0-9a-f]{64}", value["protected_profile_digest"]) is None):
        raise ValueError("Structural projector did not retain the exact Rust runtime wrapper")
    report = {"version": 1, "profileSha256": wrapper_sha,
        "protectedProfileDigest": value["protected_profile_digest"],
        "candidateFile": str(candidate_file), "candidateSha256": hashlib.sha256(candidate_file.read_bytes()).hexdigest(),
        "prepareReceipt": {name: value for name, value in receipt.items() if name != "stdout"},
        "digestReceipt": {name: value for name, value in projected.items() if name != "stdout"},
        "runtime": artifact["evidence"]["runtime"], "qualification": None,
        "scope": "current runtime preflight structural commitment; final installation must be measured anew"}
    retain_direct_flow(label + "-runtime-profile-projection.json", report)
    return report


def _run_profile_projection(arguments, label):
    """Retain the actual source-built command output before checking its result."""
    executable = Path(arguments[0])
    with executable.open("rb") as source:
        executable_sha = hashlib.file_digest(source, "sha256").hexdigest()
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
        check=False, timeout=180)
    stdout_sha = retain_direct_flow(label + ".stdout", result.stdout)
    stderr_sha = retain_direct_flow(label + ".stderr", result.stderr)
    receipt = {"version": 1, "executable": str(executable), "executableSha256": executable_sha,
        "arguments": arguments, "exitCode": result.returncode,
        "stdoutSha256": stdout_sha, "stderrSha256": stderr_sha}
    retain_direct_flow(label + "-invocation.json", receipt)
    if result.returncode:
        raise RuntimeError("Source-owned runtime projection refused; actual command output retained")
    return {**receipt, "stdout": result.stdout}
