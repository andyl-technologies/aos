"""Retains verified vendor registry hashes in the source runner's lock format."""

import hashlib
import json
from pathlib import Path
import re
import sys


def prepare_lockfile(vendor_directory: Path) -> None:
    """Verifies cached metadata before adapting the build-local lockfile."""
    lockfile = Path("MODULE.bazel.lock")
    original = json.loads(lockfile.read_text())
    schema_source = Path(
        "src/main/java/com/google/devtools/build/lib/bazel/bzlmod/BazelLockFileValue.java"
    ).read_text()
    versions = re.findall(r"LOCK_FILE_VERSION = (\d+);", schema_source)
    if len(versions) != 1:
        raise SystemExit("Expected one Bazel lockfile schema version")

    schema_version = int(versions[0])
    registry_hashes = dict(original["registryFileHashes"])
    registry = vendor_directory / "_registries" / "bcr.bazel.build"
    if not registry.is_dir():
        raise SystemExit("Missing vendored Bazel Central Registry metadata")

    for path in sorted(registry.rglob("*")):
        if path.is_symlink():
            raise SystemExit(f"Registry metadata must be self-contained: {path}")
        if not path.is_file():
            continue

        url = "https://bcr.bazel.build/" + path.relative_to(registry).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = registry_hashes.get(url)
        if expected is not None and expected != digest:
            raise SystemExit(f"Vendored registry metadata differs from its source lock: {url}")
        registry_hashes[url] = digest

    # Extension results belong to their schema and resolved module graph. A new
    # schema retains registry integrity while recomputing those results offline.
    updated = original if original["lockFileVersion"] == schema_version else {
        "lockFileVersion": schema_version,
        "selectedYankedVersions": original.get("selectedYankedVersions", {}),
        "moduleExtensions": {},
    }
    updated["registryFileHashes"] = registry_hashes
    for field, getter in [("facts", "getFacts()"), ("factsVersions", "getFactsVersions()")]:
        if getter in schema_source:
            updated.setdefault(field, {})

    lockfile.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n")


prepare_lockfile(Path(sys.argv[1]))
