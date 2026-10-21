"""Binds the public streaming-http contract tests to actual Cargo artifacts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "body_limits_require_real_eof_and_latch_failures",
    "abandoned_body_releases_its_owned_source",
    "response_delivers_headers_and_first_bytes_before_the_rest_exists",
    "upload_reaches_socket_before_producer_finishes",
    "declared_response_over_limit_is_refused_before_body_delivery",
    "undeclared_response_over_limit_cannot_turn_into_eof",
    "truncated_response_is_a_transport_failure_without_successful_eof",
    "refused_upload_preserves_source_error_and_never_sends_offending_bytes",
]


def require(condition, message):
    """Refuses incomplete compilation or execution evidence."""
    if not condition:
        raise SystemExit(message)


def captured(command, log):
    """Retains original diagnostics and bounds each selector by thirty seconds."""
    with log.open("w") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=30)
    text = log.read_text()
    sys.stdout.write(text)
    require(result.returncode == 0, "streaming HTTP proof command failed: " + str(command))
    return text


def main():
    """Checks one immutable source, one actual integration artifact and all cases."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    command = ["cargo", "test", "--frozen", "--offline", "-p", "terrane-sdk",
               "--features", "tokio", "--test", "streaming_http"]
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "streaming_http"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous streaming HTTP integration artifact")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    require(target["kind"] == ["test"] and target["crate_types"] == ["bin"]
            and Path(target["src_path"]) == workspace / "terrane/sdk/terrane-sdk/tests/streaming_http.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk/terrane-sdk"))
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and profile["test"] is True and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is True,
            "streaming HTTP integration source, profile or feature mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid streaming HTTP test executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    inventory = captured(command + ["--", "--list", "--format", "terse"], output / "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory.splitlines()
              if line.endswith(": test")]
    require(len(actual) == len(set(actual)) and set(actual) == set(CASES),
            "streaming HTTP test inventory changed")
    for case in CASES:
        text = captured(command + [case, "--", "--exact", "--nocapture", "--test-threads=1"],
                        output / (case + ".log"))
        lines = text.splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "streaming HTTP case did not execute exactly once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "streaming HTTP integration artifact changed during execution")
    require(source_hashes(workspace, source) == inputs, "streaming HTTP source changed during execution")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact, "executable_sha256": digest,
        "executed_cases": CASES, "scope": "Incremental HTTP byte transport over real sockets; no protocol or durability claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
