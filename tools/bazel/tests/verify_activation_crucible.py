"""Qualifies the static adapter's actual link, installed closure and CLI parity."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from verify_cache import execution_events
from verify_static_runtime import expanded_command


def verify(build, package, libraries, cargo, readelf):
    """Checks realized static inputs without invoking the guest doorbell."""
    binary = package / "bin/aos-ability-crucible"
    elf = {
        name: subprocess.check_output([str(readelf), flag, str(binary)], text=True)
        for name, flag in [("header", "-h"), ("program_headers", "-l"), ("dynamic", "-d")]
    }
    if (not re.search(r"Type:\s+EXEC\b", elf["header"])
            or "INTERP" in elf["program_headers"] or "(NEEDED)" in elf["dynamic"]):
        raise ValueError("installed activation adapter is not a classic static executable")

    selected = [
        event for event in execution_events(build)
        if event["targetLabel"] == "//crates/aos/activation/aos-activation-crucible:aos-ability-crucible"
        and event["mnemonic"] == "Rustc"
    ]
    if len(selected) != 1 or "sandbox" not in selected[0]["runner"] or selected[0].get("cacheHit", False):
        raise ValueError("missing actual sandboxed activation adapter link")

    event = selected[0]
    required = {
        "static/lib/" + name: libraries / "static/lib" / name
        for name in ["libc.a", "libm.a", "libgcc_eh.a"]
    }
    required["static/closure.json"] = libraries / "static/closure.json"
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in required.items()}
    for name, digest in hashes.items():
        if not any(entry["path"].endswith("/" + name)
                   and entry.get("digest", {}).get("hash") == digest for entry in event["inputs"]):
            raise ValueError("activation adapter link omitted exact static runtime input: " + name)

    graph = json.loads((build / "evidence/actions.json").read_text())
    command = expanded_command(graph, event)
    for flag in ["target-feature=+crt-static", "relocation-model=static"]:
        if not any(flag in argument for argument in command):
            raise ValueError("activation adapter link omitted " + flag)

    # Invalid argument forms exercise startup without opening a protected socket
    # or executing guest-only instrumentation instructions on the host.
    cli = []
    for arguments in [[], ["--help"], ["--invalid-operation"], ["--config"], ["--wait-ready"]]:
        actual, expected = [
            subprocess.run([str(path), *arguments], capture_output=True, text=True, timeout=30)
            for path in [binary, cargo / "bin/aos-ability-crucible"]
        ]
        if not actual.returncode or (actual.returncode, actual.stdout, actual.stderr) != (
                expected.returncode, expected.stdout, expected.stderr):
            raise ValueError("installed activation adapter CLI differs from Cargo: " + repr(arguments))
        cli.append({"arguments": arguments, "status": actual.returncode,
                    "stdout": actual.stdout, "stderr": actual.stderr})

    closure = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())["package"]
    references = {entry["path"]: entry["references"] for entry in closure}
    runtime = json.loads(required["static/closure.json"].read_text())
    if set(references[str(package)]) - {str(package), runtime["glibc"]}:
        raise ValueError("static activation adapter retains an unexpected runtime reference")

    return {
        "schema_version": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "elf": elf,
        "runtime": runtime,
        "link_command": command,
        "selected_inputs": hashes,
        "cli_parity": cli,
        "package": str(package),
        "references": references[str(package)],
        "closure": closure,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "package", "libraries", "cargo", "readelf", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    report = verify(options.build, options.package, options.libraries, options.cargo, options.readelf)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
