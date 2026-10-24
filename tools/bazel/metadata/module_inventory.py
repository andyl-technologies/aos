"""Pins source repositories from an explicitly updated Bzlmod graph.

Run only during dependency updates, after `bazel mod graph --output=json`.
Every registry response is checked against MODULE.bazel.lock before the
reviewable Nix fetch inventory is written. Ordinary builds never run this tool.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request


def collect(node, modules):
    if node.get("key") != "<root>" and node.get("version"):
        modules[node["name"]] = node["version"]
    for child in node.get("dependencies", []):
        collect(child, modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--module", type=Path, default=Path("MODULE.bazel"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    modules = {}
    collect(json.loads(args.graph.read_text()), modules)
    hashes = json.loads(args.lock.read_text())["registryFileHashes"]
    # `mod graph` omits some built-in/module-tool dependencies. The lock also
    # records selected source specifications for those repositories.
    for url in hashes:
        match = re.fullmatch(r"https://bcr\.bazel\.build/modules/([^/]+)/([^/]+)/source\.json", url)
        if match:
            modules.setdefault(*match.groups())
    inventory = {}

    for name, version in sorted(modules.items()):
        base = f"https://bcr.bazel.build/modules/{name}/{version}"
        url = f"{base}/source.json"
        with urllib.request.urlopen(url, timeout=60) as response:
            contents = response.read()
        if hashlib.sha256(contents).hexdigest() != hashes[url]:
            raise ValueError(f"registry source metadata changed: {name}@{version}")
        source = json.loads(contents)
        if "url" not in source or "integrity" not in source:
            raise ValueError(f"unsupported source specification: {name}@{version}")
        inventory[name] = {
            "version": version,
            "registry": base,
            "module_sha256": hashes[f"{base}/MODULE.bazel"],
            "source": source,
        }

    result = {
        "schema": 1,
        "workspace_module_sha256": hashlib.sha256(args.module.read_bytes()).hexdigest(),
        "module_lock_sha256": hashlib.sha256(args.lock.read_bytes()).hexdigest(),
        "modules": inventory,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
