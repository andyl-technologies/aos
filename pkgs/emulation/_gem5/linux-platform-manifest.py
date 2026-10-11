# SPDX-License-Identifier: MIT
"""Appends measured optional-platform source bindings without exact admission."""

import json
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise RuntimeError("expected installed foundation manifest and source extension")
path = Path(sys.argv[1])
manifest = json.loads(path.read_text())
extension = json.loads(Path(sys.argv[2]).read_text())
manifest["platformRecipeSha256"] = extension["recipeSha256"]
manifest["platformManifestHelperSha256"] = extension["manifestHelperSha256"]
manifest["patches"].extend(extension["patches"])
manifest["fullSystemQualified"] = False
# The installed original may inherit a readonly store input's permissions.
# Replacing the directory entry leaves it immutable until this final write.
replacement = path.with_name("source-manifest.updated.json")
replacement.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
replacement.replace(path)
