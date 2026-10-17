# SPDX-License-Identifier: GPL-2.0-or-later
"""Rebinds audited GNU libtool file probes without changing their ABI cases."""

import hashlib
import json
from pathlib import Path
import sys


def main():
    root = Path(sys.argv[1]).resolve(strict=True)
    helper = Path(sys.argv[2]).resolve(strict=True)
    catalog = json.loads(Path(sys.argv[3]).read_text())
    if not helper.is_file() or not str(helper).startswith("/nix/store/"):
        raise ValueError("The declared predecessor-built file helper is required")

    changes = []
    for row in catalog["records"]:
        path = root / row["path"]
        if path.is_symlink():
            raise ValueError("An audited probe source became a symbolic link")
        body = path.read_bytes()
        if len(body) != row["bytes"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ValueError("An original GNU probe source changed")
        if body.count(b"/usr/bin/file") != row["occurrences"]:
            raise ValueError("The audited probe occurrence count changed")
        replacement = body.replace(b"/usr/bin/file", str(helper).encode())
        if b"/usr/bin/file" in replacement:
            raise ValueError("An undeclared file probe remains")
        changes.append((path, replacement, row))

    # Authenticate every preimage before applying any normalization.
    results = []
    for path, replacement, row in changes:
        path.write_bytes(replacement)
        if path.read_bytes() != replacement:
            raise ValueError("The literal probe postimage differs")
        results.append({"path": row["path"], "original": row,
                        "bytes": len(replacement),
                        "sha256": hashlib.sha256(replacement).hexdigest()})
    (root / "aos-file-probe-normalization.json").write_text(json.dumps({
        "helper": str(helper), "records": results,
        "scope": "Only the helper executable path changed; original libtool ABI case behavior remains",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
