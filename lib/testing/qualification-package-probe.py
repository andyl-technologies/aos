"""Runs one declarative package operation and writes its exact observation.

The package qualification executor supplies only the imported package closure
and a small set of named AOS harness tools. Probe specifications use explicit
placeholders for those paths, so they cannot accidentally resolve a tool from
the qualification host.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any


PROBE_SCHEMA = "aos.release.package-probe/v1"
RESULT_SCHEMA = "aos.release.package-functional-result/v1"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_STEPS = 16
MAX_ARGUMENTS = 64
MAX_TIMEOUT_SECONDS = 300
PLACEHOLDER = re.compile(r"@[A-Za-z0-9:_-]+@")


def fail(message: str) -> None:
    """Raises one probe validation failure."""

    raise RuntimeError(message)


def require_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    """Returns an object after checking its exact member set."""

    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} does not have the required members")
    return value


def require_text(value: Any, label: str) -> str:
    """Returns one non-empty bounded string."""

    if not isinstance(value, str) or not value.strip():
        fail(f"{label} is not a non-empty string")
    if len(value.encode()) > MAX_DOCUMENT_BYTES:
        fail(f"{label} exceeds its size bound")
    return value


def load_json(path: pathlib.Path, label: str) -> Any:
    """Loads a bounded JSON file while rejecting duplicate members."""

    raw = path.read_bytes()
    if len(raw) > MAX_DOCUMENT_BYTES:
        fail(f"{label} exceeds its size bound")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} repeats member {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} is not valid JSON") from error


def canonical(value: Any) -> bytes:
    """Encodes one canonical JSON value."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def safe_relative_path(value: Any, label: str) -> pathlib.PurePosixPath:
    """Parses a relative path confined to the probe work directory."""

    text = require_text(value, label)
    path = pathlib.PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        fail(f"{label} escapes the probe work directory")
    return path


def output_paths() -> dict[str, str]:
    """Reads the exact output-name to imported-store-path mapping."""

    outputs = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_OUTPUTS"])
    if not isinstance(outputs, dict) or "out" not in outputs:
        fail("package outputs do not contain the primary output")
    for name, path in outputs.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            fail("package output has an invalid name")
        if not isinstance(path, str) or not path.startswith("/nix/store/"):
            fail("package output has an invalid store path")
    return outputs


def closure_paths() -> list[str]:
    """Reads the exact signed closure made available to the probe."""

    closure = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
    if (
        not isinstance(closure, list)
        or not closure
        or len(set(closure)) != len(closure)
        or any(
            not isinstance(path, str) or not path.startswith("/nix/store/")
            for path in closure
        )
    ):
        fail("package closure is not a unique list of Nix store paths")
    return closure


def placeholders(work: pathlib.Path, outputs: dict[str, str]) -> dict[str, str]:
    """Builds the only substitutions accepted by a probe specification."""

    values = {
        "@work@": str(work),
        "@profile@": os.environ["AOS_QUALIFICATION_PACKAGE_PROFILE"],
        "@bash@": os.environ["AOS_QUALIFICATION_BASH"],
        "@cc@": os.environ["AOS_QUALIFICATION_CC"],
        "@cxx@": os.environ["AOS_QUALIFICATION_CXX"],
        "@python@": os.environ["AOS_QUALIFICATION_PYTHON"],
    }
    for name, path in outputs.items():
        values[f"@output:{name}@"] = path
        store_hash = pathlib.Path(path).name.split("-", 1)[0]
        values[f"@profile-output:{name}@"] = str(
            pathlib.Path(values["@profile@"]) / "usr" / store_hash
        )
    values["@out@"] = outputs["out"]
    values["@profile-out@"] = values["@profile-output:out@"]
    return values


def expand(value: Any, substitutions: dict[str, str], label: str) -> str:
    """Expands every recognized path placeholder in a string."""

    text = require_text(value, label)
    for marker in PLACEHOLDER.findall(text):
        replacement = substitutions.get(marker)
        if replacement is None:
            fail(f"{label} uses unavailable placeholder {marker}")
        text = text.replace(marker, replacement)
    if "@" in text and PLACEHOLDER.search(text):
        fail(f"{label} contains an unresolved placeholder")
    return text


def write_inputs(
    root: pathlib.Path, files: Any, substitutions: dict[str, str], label: str
) -> None:
    """Creates the operation's declared regular input files."""

    if not isinstance(files, dict) or len(files) > 32:
        fail(f"{label} files are not a bounded object")
    for name, content in files.items():
        relative = safe_relative_path(name, f"{label} file name")
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            fail(f"{label} repeats input path {name}")
        destination.write_text(expand(content, substitutions, f"{label} file {name}"))


def check_stream(actual: bytes, expected: Any, label: str) -> str:
    """Checks one captured stream and returns a stable observation."""

    if expected is None:
        return f"{label}=unchecked"
    match = require_object(expected, {"exact"}, f"{label} expectation")
    exact = match["exact"]
    if not isinstance(exact, str):
        fail(f"{label} exact expectation is not a string")
    wanted = exact.encode()
    if actual != wanted:
        fail(f"{label} differs from its exact expected bytes")
    return f"{label}=sha256:{hashlib.sha256(actual).hexdigest()}"


def run_step(
    step: Any,
    index: int,
    root: pathlib.Path,
    substitutions: dict[str, str],
    allowed_command_roots: list[pathlib.Path],
    allowed_harness_commands: set[pathlib.Path],
) -> tuple[str, bool]:
    """Runs one exact command step and returns its stable observation."""

    required = {"argv", "exit_code"}
    optional = {"stdin", "stdout", "stderr", "timeout_seconds", "observes_rejection"}
    if not isinstance(step, dict) or not required <= set(step) or set(step) - required - optional:
        fail(f"step {index} has unsupported members")
    argv_value = step["argv"]
    if not isinstance(argv_value, list) or not 1 <= len(argv_value) <= MAX_ARGUMENTS:
        fail(f"step {index} argv is not a bounded non-empty list")
    argv = [expand(value, substitutions, f"step {index} argument") for value in argv_value]
    command = pathlib.Path(argv[0])
    if not command.is_absolute():
        fail(f"step {index} command is not an explicit absolute path")
    try:
        resolved_command = command.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"step {index} command cannot be resolved") from error

    command_is_probe_output = resolved_command.is_relative_to(root.resolve())
    command_is_allowed_input = any(
        resolved_command.is_relative_to(root_path.resolve())
        for root_path in allowed_command_roots
    )
    command_is_harness = resolved_command in {
        path.resolve() for path in allowed_harness_commands
    }
    if (
        not command_is_harness
        and not command_is_probe_output
        and not command_is_allowed_input
    ):
        fail(f"step {index} command is outside the package closure and harness")

    exit_code = step["exit_code"]
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        fail(f"step {index} exit code is invalid")
    timeout = step.get("timeout_seconds", 60)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= MAX_TIMEOUT_SECONDS
    ):
        fail(f"step {index} timeout is invalid")
    stdin = step.get("stdin", "")
    if not isinstance(stdin, str) or len(stdin.encode()) > MAX_DOCUMENT_BYTES:
        fail(f"step {index} stdin exceeds its size bound")

    try:
        completed = subprocess.run(
            argv,
            cwd=root,
            env=os.environ.copy(),
            input=stdin.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"step {index} exceeded {timeout} seconds") from error
    if len(completed.stdout) > MAX_DOCUMENT_BYTES or len(completed.stderr) > MAX_DOCUMENT_BYTES:
        fail(f"step {index} output exceeds its size bound")
    if completed.returncode != exit_code:
        fail(
            f"step {index} returned {completed.returncode}, expected {exit_code}: "
            + completed.stderr[-4096:].decode(errors="replace")
        )

    observations = [f"step{index}=exit:{completed.returncode}"]
    observations.append(check_stream(completed.stdout, step.get("stdout"), f"step{index}.stdout"))
    observations.append(check_stream(completed.stderr, step.get("stderr"), f"step{index}.stderr"))
    rejects = step.get("observes_rejection", False)
    if not isinstance(rejects, bool):
        fail(f"step {index} rejection marker is not a boolean")
    if rejects and exit_code == 0 and step.get("stdout") is None and step.get("stderr") is None:
        fail(f"step {index} claims rejection without an exact observation")
    return ",".join(observations), rejects or exit_code != 0


def check_artifacts(root: pathlib.Path, artifacts: Any, label: str) -> list[str]:
    """Checks exact files produced by an operation."""

    if not isinstance(artifacts, list) or len(artifacts) > 32:
        fail(f"{label} artifacts are not a bounded list")
    observations = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or set(artifact) not in (
            {"path", "text"},
            {"path", "sha256"},
        ):
            fail(f"{label} artifact {index} has unsupported members")
        relative = safe_relative_path(artifact["path"], f"{label} artifact path")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            fail(f"{label} artifact {relative} is not a regular file")
        raw = path.read_bytes()
        if len(raw) > MAX_DOCUMENT_BYTES:
            fail(f"{label} artifact {relative} exceeds its size bound")
        observed_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        if "text" in artifact:
            expected = artifact["text"]
            if not isinstance(expected, str) or raw != expected.encode():
                fail(f"{label} artifact {relative} differs from expected text")
        elif artifact["sha256"] != observed_hash:
            fail(f"{label} artifact {relative} differs from expected SHA-256")
        observations.append(f"artifact:{relative}={observed_hash}")
    return observations


def run_operation(
    value: Any,
    label: str,
    root: pathlib.Path,
    substitutions: dict[str, str],
    allowed_command_roots: list[pathlib.Path],
    allowed_harness_commands: set[pathlib.Path],
) -> dict[str, str]:
    """Runs one primary or bad-input operation."""

    operation = require_object(
        value,
        {"input", "operation", "expected", "files", "steps", "artifacts"},
        label,
    )
    descriptions = {
        name: require_text(operation[name], f"{label} {name}")
        for name in ("input", "operation", "expected")
    }
    write_inputs(root, operation["files"], substitutions, label)
    steps = operation["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        fail(f"{label} steps are not a bounded non-empty list")
    if label == "primary" and any(
        not isinstance(step, dict) or step.get("exit_code") != 0 for step in steps
    ):
        fail("primary operation contains a non-success expected status")

    observations = []
    rejection_observed = False
    for index, step in enumerate(steps, start=1):
        observed, rejected = run_step(
            step,
            index,
            root,
            substitutions,
            allowed_command_roots,
            allowed_harness_commands,
        )
        observations.append(observed)
        rejection_observed = rejection_observed or rejected
    observations.extend(check_artifacts(root, operation["artifacts"], label))
    if label == "bad_input" and not rejection_observed:
        fail("bad-input operation does not make rejection observable")

    return descriptions | {"observed": ";".join(observations)}


def main() -> None:
    """Validates the specification and executes both required operations."""

    if len(sys.argv) != 2:
        fail("usage: qualification-package-probe.py SPEC.json")
    spec = require_object(
        load_json(pathlib.Path(sys.argv[1]), "package probe specification"),
        {"schema_version", "package", "primary", "bad_input"},
        "package probe specification",
    )
    if spec["schema_version"] != PROBE_SCHEMA:
        fail("package probe specification has an unsupported schema")
    package = os.environ["AOS_QUALIFICATION_PACKAGE"]
    if spec["package"] != package:
        fail("package probe specification has another package identity")

    work = pathlib.Path(os.environ["AOS_QUALIFICATION_PROBE_WORK"])
    outputs = output_paths()
    closure = closure_paths()
    substitutions = placeholders(work, outputs)
    allowed_command_roots = [pathlib.Path(path) for path in closure]
    allowed_command_roots.extend(
        pathlib.Path(substitutions[f"@profile-output:{name}@"])
        for name in outputs
    )
    allowed_harness_commands = {
        pathlib.Path(substitutions[marker])
        for marker in ("@bash@", "@cc@", "@cxx@", "@python@")
    }
    primary_root = work / "primary"
    bad_input_root = work / "bad-input"
    primary_root.mkdir()
    bad_input_root.mkdir()

    result = {
        "schema_version": RESULT_SCHEMA,
        "package": package,
        "platform": os.environ["AOS_QUALIFICATION_PLATFORM"],
        "primary": run_operation(
            spec["primary"],
            "primary",
            primary_root,
            substitutions,
            allowed_command_roots,
            allowed_harness_commands,
        ),
        "bad_input": run_operation(
            spec["bad_input"],
            "bad_input",
            bad_input_root,
            substitutions,
            allowed_command_roots,
            allowed_harness_commands,
        ),
    }
    report = pathlib.Path(os.environ["AOS_QUALIFICATION_PROBE_REPORT"])
    report.write_bytes(canonical(result) + b"\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        print(f"package qualification probe failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
