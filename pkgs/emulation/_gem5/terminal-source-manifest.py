# SPDX-License-Identifier: MIT
"""Appends isolated terminal source bindings while preserving platform provenance."""

import json
from pathlib import Path
import sys


def main():
    manifest_path, extension_path = map(Path, sys.argv[1:])
    manifest = json.loads(manifest_path.read_text())
    extension = json.loads(extension_path.read_text())
    if manifest.get("schema") != "crucible.gem5.source-foundation.v1":
        raise ValueError("unknown native foundation source manifest")
    if "terminalSource" in manifest:
        raise ValueError("terminal source extension is already present")
    manifest["terminalSource"] = extension
    manifest["patches"].extend(extension["patches"])
    manifest["fullSystemQualified"] = False
    replacement = manifest_path.with_name("terminal-source-manifest.updated.json")
    replacement.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    replacement.replace(manifest_path)


if __name__ == "__main__":
    main()
