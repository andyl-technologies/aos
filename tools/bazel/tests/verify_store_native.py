"""Qualifies the store binary's declared native inputs and installed closure."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from verify_cache import execution_events


def verify(build, package, libraries, readelf, graph):
    """Requires selected SQLite/zstd bytes, shared SQLite, and static zstd."""
    label = "//crates/crucible/crucible-store:crucible-fleet-store"
    actions = [event for event in execution_events(build)
               if event["targetLabel"] == label and event["mnemonic"] == "Rustc"]
    if len(actions) != 1 or "sandbox" not in actions[0]["runner"]:
        raise ValueError("store binary lacks its unique sandboxed Rust compilation")
    selected = {}
    identities = {}
    for name in ["sqlite", "zstd"]:
        identity = json.loads((libraries / name / "closure.json").read_text())
        library = Path(identity["package"]) / identity["libraryFile"]
        digest = hashlib.sha256(library.read_bytes()).hexdigest()
        matches = [entry for entry in actions[0]["inputs"]
                   if entry["path"].endswith("/" + library.name)
                   and entry.get("digest", {}).get("hash") == digest]
        if not matches:
            raise ValueError(f"store Rust action omitted selected {name} library bytes")
        selected[name] = matches
        identities[name] = identity

    binary = package / "bin/crucible-fleet-store"
    dynamic = subprocess.check_output([str(readelf), "-d", str(binary)], text=True)
    needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
    if "libsqlite3.so" not in needed or any(name.startswith("libzstd") for name in needed):
        raise ValueError("installed store does not use shared SQLite and static zstd")
    if identities["sqlite"]["package"] + "/lib" not in dynamic:
        raise ValueError("installed store rpath omits selected SQLite")

    # The exported graph can include build inputs. Follow only the installed
    # package's runtime references before checking the final closure.
    by_path = {entry["path"]: entry for entry in graph}
    pending = [str(package)]
    runtime = set()
    while pending:
        path = pending.pop()
        if path in runtime:
            continue
        runtime.add(path)
        pending.extend(by_path[path]["references"])
    if identities["sqlite"]["package"] not in runtime or identities["zstd"]["package"] in runtime:
        raise ValueError("installed store closure does not match its native linkage")
    program_headers = subprocess.check_output([str(readelf), "-l", str(binary)], text=True)
    interpreters = re.findall(r"Requesting program interpreter: ([^]]+)\]", program_headers)
    if len(interpreters) != 1 or not any(interpreters[0].startswith(path + "/") for path in runtime):
        raise ValueError("installed store interpreter is outside its declared runtime closure")
    return {
        "schema_version": 1,
        "selected_inputs": selected,
        "libraries": identities,
        "needed": needed,
        "interpreter": interpreters[0],
        "runtime_closure": [{"path": path, "narHash": by_path[path]["narHash"]} for path in sorted(runtime)],
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "package", "libraries", "readelf", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    graph = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())["artifact"]
    report = verify(options.build, options.package, options.libraries, options.readelf, graph)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
