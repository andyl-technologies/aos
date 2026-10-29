"""Observe the installed emulator artifact and the actual live workerd process.

This observer hashes files and live process identity independently of Worker
claims. Its report binds a previously authenticated deployment capture to actual
installation bytes. It confers no provider, clock or queue qualification.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def hash_regular_file(path):
    """Stream a stable regular file without retaining its contents."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        first = os.fstat(source.fileno())
        if not stat.S_ISREG(first.st_mode):
            raise ValueError("installation input is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while block := source.read(1024 * 1024):
            digest.update(block)
            size += len(block)
        last = os.fstat(source.fileno())
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(first, field) != getattr(last, field) for field in identity):
        raise ValueError("installation input changed during observation")
    if size != first.st_size:
        raise ValueError("installation input length changed")
    return digest.hexdigest(), size


def process_identity(pid, expected_runtime):
    """Observe a live process lifetime and its exact executable path."""
    directory = Path("/proc") / str(pid)
    executable = (directory / "exe").resolve(strict=True)
    if executable != expected_runtime.resolve(strict=True):
        raise ValueError("live emulator executable differs from installed runtime")
    text = (directory / "stat").read_text()
    prefix, separator, tail = text.rpartition(") ")
    if not separator or not prefix.startswith(f"{pid} ("):
        raise ValueError("live emulator process identity is invalid")
    fields = tail.split()
    if len(fields) < 20 or int(fields[19]) <= 0:
        raise ValueError("live emulator process lifetime is unavailable")
    return executable, int(fields[19])


def observe_installation(options):
    """Bind authenticated audience/source facts to actual installation hashes."""
    identity_bytes = options.identity_file.read_bytes()
    if len(identity_bytes) > 256 * 1024:
        raise ValueError("authenticated deployment identity exceeds bounds")
    identity = json.loads(identity_bytes)
    source_digest = identity["sourceDigest"]
    script_version = identity["scriptVersion"]
    if identity["version"] != 1 or not re.fullmatch(r"[0-9a-f]{64}", source_digest):
        raise ValueError("authenticated emulator source identity is invalid")
    if script_version != f"emulated-{source_digest}":
        raise ValueError("authenticated emulator script identity differs from source")
    if not identity["externalProfiles"] or identity["managedProfile"] is not None:
        raise ValueError("installation is not an External emulator deployment")

    raw_pid = options.process_pid_file.read_text().strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", raw_pid):
        raise ValueError("live emulator process identifier is invalid")
    pid = int(raw_pid)
    before = process_identity(pid, options.runtime_file)
    runtime_hash, _ = hash_regular_file(options.runtime_file)
    observed_hash, _ = hash_regular_file(Path("/proc") / str(pid) / "exe")
    after = process_identity(pid, options.runtime_file)
    if before != after or runtime_hash != observed_hash:
        raise ValueError("live emulator executable changed during observation")

    wasm_hash, wasm_size = hash_regular_file(options.wasm_file)
    shim_hash, shim_size = hash_regular_file(options.shim_file)
    source_nar_hash, _ = hash_regular_file(options.source_nar_file)
    distribution_nar_hash, _ = hash_regular_file(options.distribution_nar_file)
    runner_hash, _ = hash_regular_file(options.runner_file)
    bindings_hash, _ = hash_regular_file(options.runtime_bindings_file)
    # WireInteger values remain decimal strings, as in the shared closed schema.
    return {
        "version": 1,
        "executionKind": "emulated_external",
        "sourceDigest": source_digest,
        "scriptVersion": script_version,
        "deploymentId": identity["deploymentId"],
        "publicOrigin": identity["publicOrigin"],
        "sourceNarSha256": source_nar_hash,
        "distributionNarSha256": distribution_nar_hash,
        "wasmSha256": wasm_hash,
        "wasmByteSize": str(wasm_size),
        "shimSha256": shim_hash,
        "shimByteSize": str(shim_size),
        "runnerSha256": runner_hash,
        "runtimeExecutableSha256": runtime_hash,
        "observedProcessExecutableSha256": observed_hash,
        "runtimeBindingsSha256": bindings_hash,
    }


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "identity-file", "source-nar-file", "distribution-nar-file", "wasm-file",
        "shim-file", "runner-file", "runtime-file", "runtime-bindings-file",
        "process-pid-file", "report-file",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    options = parser.parse_args()
    report = observe_installation(options)
    descriptor = os.open(options.report_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print("Installed emulator artifact observation retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("installed emulator artifact observation failed") from None
