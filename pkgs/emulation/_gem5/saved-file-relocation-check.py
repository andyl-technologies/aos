# SPDX-License-Identifier: MIT
"""Checks the compiled saved-copy hook against authentic files and bad rosters."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


EXECUTABLE = sys.argv[1]
KEYS = ("CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT",
        "CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT",
        "CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST")


def fixture(root):
    source = root / "deleted" / "ckpt_original_files"
    target = root / "imported" / "ckpt_original_files"
    target.parent.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    records = []
    for name, data in (("guest_10", b"known guest asset\x00"),
                       ("stats_11", b"counter at original native cut\n")):
        leaf = target / name
        leaf.write_bytes(data)
        leaf.chmod(0o400)
        records.append(f"{hashlib.sha256(data).hexdigest()}\t{len(data)}\t{name}")
    manifest = root / "roster"
    manifest.write_text("\n".join(("crucible-saved-files-v1", str(source),
                                   str(target), *records)) + "\n")
    manifest.chmod(0o400)
    return source, target, manifest


def rewrite(path, transform):
    path.chmod(0o600)
    path.write_bytes(transform(path.read_bytes()))
    path.chmod(0o400)


def run_case(name, change=None, expected=125):
    with tempfile.TemporaryDirectory(prefix="native-saved-copy-") as directory:
        root = Path(directory).resolve()
        source, target, manifest = fixture(root)
        environment = {key: value for key, value in os.environ.items() if key not in KEYS}
        environment.update(dict(zip(KEYS, map(str, (source, target, manifest)))))
        original = str(source / "stats_11")
        if change:
            original = change(source, target, manifest, environment, original) or original
        result = subprocess.run([EXECUTABLE, original], env=environment,
                                capture_output=True, timeout=10, check=False)
        if result.returncode != expected:
            raise AssertionError(f"{name}: {result.returncode}: {result.stderr.decode()}")
        if expected == 0 and result.stdout != (str(target / "stats_11") + "\n").encode():
            raise AssertionError(f"{name}: wrong relocated path")
        if expected == 125 and b"invalid native saved-copy relocation:" not in result.stderr:
            raise AssertionError(f"{name}: native refusal reason absent")


def mutate_leaf(target, mode):
    leaf = target / "stats_11"
    if mode == "content":
        leaf.chmod(0o600)
        leaf.write_bytes(b"unrelated artifact\n")
    elif mode == "hardlink":
        os.link(leaf, target.parent / "alias")
    elif mode == "symlink":
        moved = target.parent / "outside"
        leaf.rename(moved)
        leaf.symlink_to(moved)
    elif mode == "missing":
        leaf.unlink()


run_case("genuine complete roster after original namespace removal", expected=0)
run_case("partial restart binding", lambda s, t, m, e, o: e.pop(KEYS[2]))
run_case("unrelated original prefix", lambda s, t, m, e, o: str(s.parent / "other_files" / "stats_11"))
run_case("nested original leaf", lambda s, t, m, e, o: str(s / "nested" / "stats_11"))
run_case("unknown original leaf", lambda s, t, m, e, o: str(s / "unknown"))
run_case("noncanonical target", lambda s, t, m, e, o: e.__setitem__(KEYS[1], str(t) + "/../" + t.name))
run_case("source-target alias", lambda s, t, m, e, o: e.__setitem__(KEYS[0], str(t)))
run_case("nonprivate directory", lambda s, t, m, e, o: t.chmod(0o755))
run_case("writable roster", lambda s, t, m, e, o: m.chmod(0o600))
run_case("hardlinked roster", lambda s, t, m, e, o: os.link(m, m.with_name("alias")))
run_case("incorrect header", lambda s, t, m, e, o: rewrite(m, lambda b: b.replace(b"crucible-saved-files-v1", b"other-schema")))
run_case("another root binding", lambda s, t, m, e, o: rewrite(m, lambda b: b.replace(str(s).encode(), str(s.parent).encode())))
run_case("uppercase digest", lambda s, t, m, e, o: rewrite(m, lambda b: b.replace(b"\n" + b.splitlines()[3], b"\n" + b.splitlines()[3].upper())))
run_case("noncanonical length", lambda s, t, m, e, o: rewrite(m, lambda b: b.replace(b"\t", b"\t0", 1)))
run_case("reordered roster", lambda s, t, m, e, o: rewrite(m, lambda b: b"\n".join(b.splitlines()[:3] + list(reversed(b.splitlines()[3:]))) + b"\n"))
run_case("duplicate roster row", lambda s, t, m, e, o: rewrite(m, lambda b: b + b.splitlines()[-1] + b"\n"))
run_case("truncated roster", lambda s, t, m, e, o: rewrite(m, lambda b: b[:-1]))
run_case("embedded NUL", lambda s, t, m, e, o: rewrite(m, lambda b: b.replace(b"crucible", b"crucible\x00")))
run_case("unlisted extra leaf", lambda s, t, m, e, o: (t / "extra").write_bytes(b"extra") and None)
run_case("unlisted extra directory", lambda s, t, m, e, o: (t / "extra").mkdir())
for mutation in ("content", "hardlink", "symlink", "missing"):
    run_case("leaf " + mutation,
             lambda s, t, m, e, o, mutation=mutation: mutate_leaf(t, mutation))

# Absence preserves stock DMTCP behavior. Supplying any incomplete replacement
# binding never silently falls back to an original external namespace.
environment = {key: value for key, value in os.environ.items() if key not in KEYS}
stock = subprocess.run([EXECUTABLE, "/original/ckpt_files/leaf"], env=environment,
                       capture_output=True, timeout=10, check=True)
assert stock.stdout == b"\n"
print("native saved-copy relocation: 25 cases passed")
