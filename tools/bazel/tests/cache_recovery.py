"""Qualifies missing and corrupt cache blobs using private disposable caches."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time

from export_packages import completed_manifests, export_manifest
from verify_cache import execution_events, require_action


STREAM_MESSAGE = "AOS disk cache streaming verification "
STREAM_OUTPUT = (STREAM_MESSAGE * 2048 + "\n").encode()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class RecoveryTrial:
    def __init__(self, options, scratch):
        self.options = options
        self.root = scratch
        self.cache = scratch / "cache"
        self.cache.mkdir()
        self.evidence = {"schema_version": 1, "cases": {}}

    def build(self, name, allow_failure=False, delayed=False, interrupt=False):
        directory = self.root / name
        directory.mkdir()
        workspace = directory / "workspace"
        shutil.copytree(self.options.source, workspace, symlinks=True)
        for path in [workspace, *workspace.rglob("*")]:
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o200)
        shutil.copyfile(self.options.lock, workspace / "MODULE.bazel.lock")
        generator = workspace / "tools/bazel/tests/fixture/generate.py"
        source = generator.read_text() + '\nprint(' + repr(STREAM_MESSAGE) + ' * 2048)\n'
        if delayed:
            marker = "header, rust = options.outputs\n"
            if source.count(marker) != 1:
                raise ValueError("interruption fixture no longer matches its generator")
            source = source.replace(marker, marker +
                'header.write_text("incomplete cache recovery artifact\\n")\n'
                '__import__("time").sleep(10)\n')
        generator.write_text(source)
        evidence = directory / "evidence"
        evidence.mkdir()
        command = [
            sys.executable, str(self.options.launcher),
            "--config", str(self.options.config), "--workspace", str(workspace),
            "--output-base", str(directory / "output"), "--cache", str(self.cache),
            "--nix-sandbox", "--metrics", str(evidence / "metrics.json"),
            "--", "build", "//tools/bazel/tests/fixture:package",
            "--execution_log_json_file=" + str(evidence / "execution.json"),
            "--build_event_json_file=" + str(evidence / "events.json"),
        ]
        with (evidence / "build.log").open("w") as log:
            if interrupt:
                status = self.interrupt(command, log, directory)
            else:
                status = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
        if status:
            if allow_failure:
                return directory, None
            raise ValueError(f"cache recovery build failed: {name}; see {evidence / 'build.log'}")

        events = [json.loads(line) for line in (evidence / "events.json").read_text().splitlines() if line]
        packages = directory / "packages"
        artifacts = {}
        for manifest in completed_manifests(events):
            _, identifier = export_manifest(manifest, packages)
            metadata = json.loads((packages / identifier / "manifest.json").read_text())
            artifacts.update({entry["destination"]: packages / identifier / "files" / entry["destination"]
                              for entry in metadata["artifacts"]})
        if len(artifacts) != 3:
            raise ValueError(f"unexpected package artifact inventory: {name}")
        return directory, artifacts

    def interrupt(self, command, log, directory):
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 60
        pattern = "sandbox/linux-sandbox/*/execroot/_main/bazel-out/*/bin/tools/bazel/tests/fixture/generated.h"
        try:
            while process.poll() is None and time.monotonic() < deadline:
                outputs = list((directory / "output").glob(pattern))
                if any(path.read_text() == "incomplete cache recovery artifact\n" for path in outputs):
                    os.killpg(process.pid, signal.SIGINT)
                    status = process.wait(timeout=20)
                    if status == 0:
                        raise ValueError("interrupted Bazel action unexpectedly reported success")
                    return status
                time.sleep(0.1)
            raise ValueError("interruption fixture did not reach a partial declared output")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()

    def check(self, name, build, artifacts, oracle):
        actual = {name: digest(path) for name, path in artifacts.items()}
        if actual != oracle:
            raise ValueError(f"cache restored corrupt package bytes: {name}")
        for destination, path in artifacts.items():
            result = subprocess.run([str(path)], check=True, text=True, capture_output=True)
            expected = "answer=84" if destination == "bin/native-fixture" else "answer=42"
            if result.stdout.strip() != expected:
                raise ValueError(f"cache restored incorrect runtime behavior: {name}: {destination}")
        self.evidence["cases"][name] = {"artifacts": actual, "metrics": json.loads((build / "evidence/metrics.json").read_text())}

    def cached_blob(self, expected):
        candidates = [path for path in self.cache.rglob(expected) if path.is_file() and "cas" in path.parts]
        if len(candidates) != 1:
            raise ValueError("expected one output blob in the private disk cache")
        return candidates[0]

    def check_corruption(self, name, oracle, target, mnemonic, blob):
        expected_digest = blob.name
        actual_digest = digest(blob)
        if expected_digest == actual_digest:
            raise ValueError("cache corruption injection did not change the blob digest")
        build, artifacts = self.build(name, allow_failure=True)
        if artifacts is None:
            log = (build / "evidence/build.log").read_text()
            mismatch = "Expected digest" in log and "received digest" in log
            # Lazy output materialization can surface the rejected blob as a
            # missing digest when a downstream symlink action finalizes.
            missing = "Missing digest: " + expected_digest + "/" in log
            if not mismatch and not missing:
                raise ValueError("corrupt-blob build failed without a digest-mismatch diagnostic")
            self.evidence["cases"][name] = {"result": "rejected"}
        else:
            self.check(name, build, artifacts, oracle)
            require_action(execution_events(build), "//tools/bazel/tests/fixture:" + target, mnemonic, False)
            self.evidence["cases"][name]["result"] = "rebuilt"
        self.evidence["cases"][name].update({"expected_blob_digest": expected_digest, "corrupt_blob_digest": actual_digest})

    def run(self):
        cold, original = self.build("cold")
        oracle = {name: digest(path) for name, path in original.items()}
        self.check("cold", cold, original, oracle)
        warm, artifacts = self.build("warm")
        self.check("warm", warm, artifacts, oracle)
        require_action(execution_events(warm), "//tools/bazel/tests/fixture:rust_library", "Rustc", True)

        # Find the actual compiler output CAS entry by content, independently of
        # Bazel's sharding layout. Only this trial's private cache is modified.
        expected = oracle["bin/rust-fixture"]
        blob = self.cached_blob(expected)
        blob.unlink()
        missing, artifacts = self.build("missing-blob")
        self.check("missing-blob", missing, artifacts, oracle)
        require_action(execution_events(missing), "//tools/bazel/tests/fixture:rust_app", "Rustc", False)
        require_action(execution_events(missing), "//tools/bazel/tests/fixture:rust_library", "Rustc", True)

        # Captured stdout uses the streaming download path rather than the
        # path-backed copy/reflink path exercised by the compiler artifact.
        stdout_blob = self.cached_blob(hashlib.sha256(STREAM_OUTPUT).hexdigest())
        stdout_blob.write_bytes(STREAM_OUTPUT[:-1] + b"!")
        self.check_corruption("corrupt-stream", oracle, "generated", "AosPythonGenerate", stdout_blob)
        stdout_blob.unlink(missing_ok=True)

        data = blob.read_bytes()
        blob.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        self.check_corruption("corrupt-blob", oracle, "rust_app", "Rustc", blob)

        # A rejected corrupt blob must be recoverable after eviction. Never
        # depend on a previous execution tree when retrying the build.
        shutil.rmtree(self.cache)
        self.cache.mkdir()
        evicted, artifacts = self.build("evicted")
        self.check("evicted", evicted, artifacts, oracle)
        require_action(execution_events(evicted), "//tools/bazel/tests/fixture:rust_library", "Rustc", False)

        self.build("interrupted", allow_failure=True, delayed=True, interrupt=True)
        blobs = [path for path in self.cache.rglob("*") if path.is_file() and "cas" in path.parts]
        if not blobs or any(digest(path) != path.name for path in blobs):
            raise ValueError("interrupted build published an invalid content-addressed blob")
        self.evidence["cases"]["interrupted"] = {"result": "cancelled-during-partial-output", "verified_cas_blobs": len(blobs)}
        resumed, artifacts = self.build("resumed", delayed=True)
        self.check("resumed", resumed, artifacts, oracle)
        require_action(execution_events(resumed), "//tools/bazel/tests/fixture:generated", "AosPythonGenerate", False)
        return self.evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "lock", "config", "launcher", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aos-cache-recovery-") as directory:
        trial = RecoveryTrial(options, Path(directory))
        try:
            evidence = trial.run()
            (options.output / "recovery.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        finally:
            # Retain logs for a failing Nix build without retaining output bases.
            for path in Path(directory).glob("*/evidence/build.log"):
                destination = options.output / (path.parent.parent.name + ".log")
                shutil.copyfile(path, destination)
                if sys.exc_info()[0] is not None:
                    print(destination.name + ":\n" + path.read_text()[-8000:], file=sys.stderr)


if __name__ == "__main__":
    main()
