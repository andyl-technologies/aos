"""Checks native-library action inputs, ABI behavior, and runtime dependencies."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from family_libtest import bazel_binaries
from verify_cache import execution_events


def verify(build, libraries, readelf):
    """Requires both language consumers to use the selected AOS library variants."""
    prefix = "//tools/bazel/tests/native-libraries:"
    labels = [prefix + name for name in ["c_app", "rust_app"]]
    events = [json.loads(line) for line in (build / "evidence/events.json").read_text().splitlines()]
    binaries = bazel_binaries(events, labels)
    execution = execution_events(build)
    identities = {name: json.loads((libraries / name / "closure.json").read_text())
                  for name in ["sqlite", "zstd"]}
    actions = {}
    for label, mnemonic in [(prefix + "probe", "CppCompile"),
                            (prefix + "c_app", "CppLink"), (prefix + "rust_app", "Rustc")]:
        matches = [event for event in execution if event["targetLabel"] == label and event["mnemonic"] == mnemonic]
        if len(matches) != 1 or "sandbox" not in matches[0]["runner"]:
            raise ValueError(f"missing sandboxed native-library consumer: {label}")
        event = matches[0]
        inputs = [entry["path"] for entry in event["inputs"]]
        selected_libraries = {}
        for name, identity in identities.items():
            expected = f"/{name}/include/" if mnemonic == "CppCompile" else f"/{name}/closure.json"
            if not any(expected in path for path in inputs):
                raise ValueError(f"consumer omitted declared {name} inputs: {label}")
            if mnemonic != "CppCompile":
                library = Path(identity["package"]) / identity["libraryFile"]
                digest = hashlib.sha256(library.read_bytes()).hexdigest()
                # rules_cc can stage shared imports through a _solib symlink.
                # Its declared action input must still contain the exact bytes.
                selected = [entry for entry in event["inputs"]
                            if entry.get("digest", {}).get("hash") == digest
                            and entry["path"].endswith("/" + library.name)]
                if not selected:
                    candidates = [entry for entry in event["inputs"] if library.name in entry["path"]]
                    raise ValueError(f"consumer omitted selected {name} library bytes: {label}: {candidates}")
                selected_libraries[name] = selected
        actions[label] = {"mnemonic": mnemonic, "input_count": len(inputs),
                          "selected_libraries": selected_libraries}

    test_root = build / "evidence/tests"
    results = json.loads((test_root / "index.json").read_text())["results"]
    if len(results) != 1 or results[0]["identity"]["label"] != prefix + "doc" or results[0]["status"] != "PASSED":
        raise ValueError("native-library doctest did not pass exactly once")
    doctest = (test_root / results[0]["outputs"]["test.log"]).read_text()
    if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in doctest:
        raise ValueError("native-library doctest did not execute its ABI assertion")

    artifacts = {}
    for label, binary in binaries.items():
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        if result.returncode != 0 or result.stdout != "native-libraries=42\n":
            raise ValueError(f"native ABI probe failed: {label}: status={result.returncode}: {result.stdout}{result.stderr}")
        dynamic = subprocess.check_output([str(readelf), "-d", str(binary)], text=True)
        for name, identity in identities.items():
            soname = "libsqlite3.so" if name == "sqlite" else "libzstd.so"
            shared = identity["linkage"] == "shared"
            if shared != (soname in dynamic):
                raise ValueError(f"runtime linkage differs from selected {name} variant: {label}")
            if shared and identity["package"] + "/lib" not in dynamic:
                raise ValueError(f"runtime dependency omitted selected {name} variant: {label}")
        artifacts[label] = {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                            "stdout": result.stdout, "dynamic": dynamic}
    return {"schema_version": 1, "libraries": identities, "actions": actions, "artifacts": artifacts, "doctest": doctest}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "libraries", "readelf"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    report = verify(options.build, options.libraries, options.readelf)
    (options.build / "evidence/native-libraries.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
