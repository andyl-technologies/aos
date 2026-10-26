"""Exercises installed filesystem effects inside an isolated qualification VM."""

import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def invocation(package, path, identity, kind="directory", mode="0700", source=None):
    """Constructs the same resolved process contract used by activation."""
    inputs = {"path": str(path), "kind": kind, "mode": mode, "owner": None, "group": None}
    if source is not None:
        inputs["sourcePath"] = str(source)
    return {
        "id": identity, "revision": "revision-one", "action": "apply", "previous": None,
        "input": inputs,
        "effect": {
            "owner": "filesystem", "identity": ["qualification", "filesystem", "entry", identity],
            "input": inputs, "inputs": {}, "input_type": {"kind": "submodule", "open": True, "fields": {}},
            "after": [], "results": {"path": {"kind": "string"}, "resource": {"kind": "string"}},
            "handler": {"kind": "process", "artifact": str(package),
                        "executable": str(package / "bin/aos-filesystem-provider")},
            "dependencies": [], "revision": "revision-one", "lifetime": "instance", "timeout_ms": 1000,
        },
    }


def call(package, action, request, reject=False):
    """Runs the installed command and requires the expected protocol outcome."""
    request = copy.deepcopy(request)
    request["action"] = "remove" if action == "remove" else "apply"
    result = subprocess.run(
        [str(package / "bin/aos-filesystem-provider"), action],
        input=json.dumps(request).encode(), capture_output=True, timeout=15,
    )
    if reject:
        if result.returncode != 1 or result.stdout or not result.stderr.startswith(b"aos-filesystem-provider:"):
            raise ValueError("installed filesystem command accepted an unauthorized mutation")
        return None
    if result.returncode or result.stderr:
        raise ValueError("installed filesystem command failed: " + result.stderr.decode())
    return json.loads(result.stdout)


def main():
    package = Path(sys.argv[1])
    if os.getuid() != 0:
        raise ValueError("filesystem production-path qualification requires its isolated root VM")
    root = Path("/var/lib/rfc-0028-filesystem-qualification")
    root.mkdir(parents=True)
    completed = []

    directory = root / "directory"
    request = invocation(package, directory, "directory")
    directory.mkdir()
    call(package, "apply", request, reject=True)
    call(package, "remove", request, reject=True)
    directory.rmdir()
    completed.append("unclaimed-directory-apply-and-removal-rejected")

    assert call(package, "apply", request) == {"path": str(directory), "resource": "directory"}
    assert call(package, "observe", request)["status"] == "current"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    directory.chmod(0o755)
    assert call(package, "observe", request)["status"] == "retry-safe"
    call(package, "apply", request)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    completed.append("claimed-directory-metadata-drift-reconciled")

    retained = root / "retained-directory"
    original_inode = directory.stat().st_ino
    directory.rename(retained)
    directory.symlink_to(retained)
    call(package, "apply", request, reject=True)
    call(package, "remove", request, reject=True)
    assert directory.is_symlink() and retained.is_dir()
    directory.unlink()
    completed.append("replaced-directory-symlink-rejected-with-target-preserved")

    directory.mkdir(mode=0o700)
    assert directory.stat().st_ino != original_inode
    assert call(package, "observe", request)["status"] == "current"
    call(package, "apply", request)
    call(package, "remove", request)
    assert not directory.exists() and retained.is_dir()
    call(package, "remove", request)
    completed.append("directory-rematerialization-and-idempotent-release")

    mutable = root / "mutable-file"
    request = invocation(package, mutable, "mutable", "empty-file", "0600")
    call(package, "apply", request)
    mutable.write_bytes(b"application-owned contents\n")
    inode = mutable.stat().st_ino
    request["revision"] = "revision-two"
    request["input"]["mode"] = "0640"
    call(package, "apply", request)
    assert mutable.read_bytes() == b"application-owned contents\n" and mutable.stat().st_ino == inode
    assert stat.S_IMODE(mutable.stat().st_mode) == 0o640
    assert call(package, "observe", request)["status"] == "current"
    call(package, "remove", request)
    assert not mutable.exists()
    completed.append("mutable-file-contents-and-inode-preserved")

    copied = root / "copied-file"
    source = Path(__file__)
    request = invocation(package, copied, "copied", "copied-file", "0640", source)
    call(package, "apply", request)
    assert copied.read_bytes() == source.read_bytes()
    copied.write_bytes(b"drift")
    assert call(package, "observe", request)["status"] == "retry-safe"
    call(package, "apply", request)
    assert copied.read_bytes() == source.read_bytes()
    call(package, "remove", request)
    assert not copied.exists() and source.is_file()
    completed.append("copied-file-content-drift-reconciled")

    tree = root / "immutable-tree"
    request = invocation(package, tree, "tree", "symlink-tree", "0777", package / "bin")
    call(package, "apply", request)
    assert tree.is_symlink() and tree.resolve() == package / "bin"
    assert call(package, "observe", request)["status"] == "current"
    call(package, "remove", request)
    assert not tree.is_symlink() and (package / "bin").is_dir()
    completed.append("immutable-tree-link-released-without-removing-source")

    retained.rmdir()
    root.rmdir()
    print("FILESYSTEM_PROVIDER_REPORT:" + json.dumps({"status": "PASS", "cases": completed}, sort_keys=True))


if __name__ == "__main__":
    main()
