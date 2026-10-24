"""Qualifies the installed guest's static inputs, metadata, and CLI parity."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from guest_build_info import build_info
from verify_cache import execution_events
from verify_static_runtime import expanded_command


def verify(build, package, libraries, cargo, source, system, readelf):
    """Checks uncached link execution and compares the retained Cargo guest."""
    binary = package / "bin/crucible-guest"
    elf = {name: subprocess.check_output([str(readelf), flag, str(binary)], text=True)
           for name, flag in [("header", "-h"), ("program_headers", "-l"), ("dynamic", "-d")]}
    if not re.search(r"Type:\s+EXEC\b", elf["header"]) or "INTERP" in elf["program_headers"] or "(NEEDED)" in elf["dynamic"]:
        raise ValueError("installed guest is not a classic static executable")

    metadata = (package / "nix-support/crucible-guest-build-info").read_text()
    if metadata != build_info(source.read_text(), system):
        raise ValueError("installed guest metadata differs from the declared instruction ABI")

    events = execution_events(build)
    selected = [event for event in events if event["targetLabel"] ==
                "//crates/crucible/crucible-guest:crucible-guest" and event["mnemonic"] == "Rustc"]
    if len(selected) != 1 or "sandbox" not in selected[0]["runner"] or selected[0].get("cacheHit", False):
        raise ValueError("missing actual sandboxed guest link")
    event = selected[0]
    required = {f"static/lib/{name}": libraries / "static/lib" / name
                for name in ["libc.a", "libm.a", "libgcc_eh.a"]}
    required["static/closure.json"] = libraries / "static/closure.json"
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in required.items()}
    for path, digest in hashes.items():
        if not any(entry["path"].endswith("/" + path) and entry.get("digest", {}).get("hash") == digest
                   for entry in event["inputs"]):
            raise ValueError(f"guest link omitted exact static runtime input: {path}")
    graph = json.loads((build / "evidence/actions.json").read_text())
    command = expanded_command(graph, event)
    for flag in ["target-feature=+crt-static", "relocation-model=static"]:
        if not any(flag in argument for argument in command):
            raise ValueError(f"guest link omitted {flag}")

    parity = []
    for arguments in [[], ["--help"], ["-h"], ["aos-invalid-operation"],
                      ["agent", "--aos-invalid-option"], ["selectable", "aos-invalid-operation"]]:
        results = [subprocess.run([str(path), *arguments], capture_output=True, text=True, timeout=30)
                   for path in [binary, cargo / "test-binaries/crucible-guest"]]
        actual, expected = results
        if (actual.returncode, actual.stdout, actual.stderr) != (expected.returncode, expected.stdout, expected.stderr):
            raise ValueError(f"installed guest CLI differs from Cargo: {arguments}")
        parity.append({"arguments": arguments, "status": actual.returncode,
                       "stdout": actual.stdout, "stderr": actual.stderr})
    return {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "elf": elf, "metadata": metadata, "runtime": json.loads(required["static/closure.json"].read_text()),
            "link_command": command, "selected_inputs": hashes, "cli_parity": parity}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "package", "libraries", "cargo", "source", "readelf", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--system", required=True)
    options = parser.parse_args()
    report = verify(options.build, options.package, options.libraries, options.cargo,
                    options.source, options.system, options.readelf)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
