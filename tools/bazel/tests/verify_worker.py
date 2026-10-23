"""Compares the Worker deployment contract and compiled features with Cargo."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from verify_protocol import compare_features


def artifact(path):
    """Returns the immutable identity of one deployment artifact."""
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size}


def wasm_exports(node, path):
    """Validates a complete module with the declared source-built runtime."""
    script = """
const fs = require('node:fs');
const module = new WebAssembly.Module(fs.readFileSync(process.argv[1]));
process.stdout.write(JSON.stringify(WebAssembly.Module.exports(module)));
"""
    exports = json.loads(subprocess.check_output([str(node), "-e", script, str(path)], text=True))
    return {entry["name"]: entry["kind"] for entry in exports}


def compare(bazel, cargo, build, node, packages, test_hooks):
    """Requires identical assets, public Wasm exports and Cargo feature units."""
    assets = {}
    exports = {}
    for role, root in [("bazel", bazel), ("cargo", cargo)]:
        assets[role] = {
            str(path.relative_to(root)): artifact(path)
            for path in sorted((root / "assets").rglob("*")) if path.is_file()
        }
        if len(assets[role]) != 11:
            raise ValueError(f"incomplete {role} Worker asset inventory")
        for name in ["index.wasm", "shim.mjs"]:
            data = (root / name).read_bytes()
            if not test_hooks and any(marker in data for marker in [b"/_e2e/", b"aos_e2e_surface_", b"workerd-e2e"]):
                raise ValueError(f"test hooks leaked into the {role} production deployment")
        if "./index.wasm" not in (root / "shim.mjs").read_text():
            raise ValueError(f"{role} shim lost its deployed Wasm import")
        exports[role] = wasm_exports(node, root / "index.wasm")
    if assets["bazel"] != assets["cargo"]:
        raise ValueError("Bazel/Cargo Worker static assets differ")

    # Bindgen's numbered element trampolines encode compiler-private function
    # indices. Each deployment carries its matching generated JavaScript glue.
    public_exports = {
        role: {name: kind for name, kind in entries.items()
               if not re.fullmatch(r"__wasm_bindgen_func_elem_\d+", name)}
        for role, entries in exports.items()
    }
    if public_exports["bazel"] != public_exports["cargo"]:
        raise ValueError("Bazel/Cargo Worker Wasm export contracts differ")
    features = compare_features(build / "inventory.json", cargo / "cargo-messages.jsonl", packages,
                                required_packages=["aos-hub-worker"])
    return {
        "status": "PASS", "bazel": str(bazel), "cargo": str(cargo), "build": str(build),
        "assets": assets["bazel"], "exports": exports, "public_exports": public_exports["bazel"],
        "artifacts": {role: {name: artifact(root / name) for name in ["index.wasm", "shim.mjs"]}
                      for role, root in [("bazel", bazel), ("cargo", cargo)]},
        "features": features,
        "runtime_scope": "Module validation; the real workerd Durable Object VM gate is separate.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["bazel", "cargo", "build", "node", "packages", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--test-hooks", action="store_true")
    options = parser.parse_args()
    result = compare(options.bazel, options.cargo, options.build, options.node,
                     json.loads(options.packages.read_text()), options.test_hooks)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
