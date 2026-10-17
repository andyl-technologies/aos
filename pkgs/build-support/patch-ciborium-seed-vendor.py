"""Apply the pinned borrowed-seed API without changing archive provenance."""

import hashlib
import json
import stat
import subprocess
import sys
import tomllib
from pathlib import Path


BEFORE = "d42cf7486385401290cdd52b3fcccd3287837c45071c93b51ddbbd34b9a79a2b"
AFTER = "3de46b0c830f0fd374f5bffc9a1b0dc2ae29eb0431dbee64630e36e2a02480d7"
PACKAGE = "42e69ffd6f0917f5c029256a24d0161db17cea3997d185db0d35926308770f0e"
PATCH = "ad91e59027dde7c0cbf6c57bf7ab7f29ec69beaddf614bb8d07bf196857101b3"
MEMBER = "src/de/mod.rs"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply(vendor, patch, patch_program):
    crate = vendor / "source-registry-0/ciborium-0.2.2"
    members = [crate / name for name in ("Cargo.toml", ".cargo-checksum.json", MEMBER)]
    ancestors = [vendor, vendor / "source-registry-0", crate, crate / "src", crate / "src/de"]
    if any(path.is_symlink() or not path.is_dir() for path in ancestors):
        raise ValueError("Pinned CBOR source has an indirect parent directory")
    if any(path.is_symlink() or not path.is_file() for path in members):
        raise ValueError("Pinned CBOR source layout is missing or indirect")

    manifest, checksum_file, body = members
    package = tomllib.loads(manifest.read_text())["package"]
    checksum = json.loads(checksum_file.read_text())
    if package["name"] != "ciborium" or package["version"] != "0.2.2":
        raise ValueError("Pinned CBOR package identity changed")
    if checksum["package"] != PACKAGE or digest(body) != BEFORE or digest(patch) != PATCH:
        raise ValueError("Pinned CBOR source or archive identity changed")
    if checksum["files"].get(MEMBER, BEFORE) != BEFORE:
        raise ValueError("Pinned CBOR member checksum changed")

    # Nix source outputs are read-only. Only the two replaced files and their
    # parent directories need write permission; every other file is untouched.
    for path in (crate, body.parent, checksum_file, body):
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
    subprocess.run(
        [str(patch_program), "--batch", "--fuzz=0", "-p1", "-i", str(patch.resolve())],
        cwd=crate,
        check=True,
    )
    if digest(body) != AFTER:
        raise ValueError("Patched CBOR member differs from the reviewed source")

    checksum["files"][MEMBER] = AFTER
    checksum_file.write_text(json.dumps(checksum, sort_keys=True) + "\n")


if __name__ == "__main__":
    apply(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
