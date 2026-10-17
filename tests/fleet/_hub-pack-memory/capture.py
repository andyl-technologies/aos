"""Capture only the selected committed public source before any compilation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

COMMIT = "c33422854f98185bdbbb796e386edf3d41a50c36"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def capture(repository, output, git, git_sha256):
    """Retain a fresh exact Git archive and complete canonical source census."""
    repository, output, git = Path(repository), Path(output), Path(git)
    if (not output.is_absolute() or output.exists() or not str(git).startswith("/nix/store/")
            or hashlib.sha256(git.read_bytes()).hexdigest() != git_sha256):
        raise ValueError("capture root or selected source-built Git differs")
    output.mkdir(mode=0o700)
    archive = output / "source.tar"
    with archive.open("xb") as stream:
        invocation = subprocess.run([str(git), "-C", str(repository), "archive", COMMIT],
            stdout=stream, stderr=subprocess.PIPE, timeout=120, check=False)
    (output / "archive.stderr").write_bytes(invocation.stderr)
    if invocation.returncode or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive failed or exceeded its source-only bound")
    tree = subprocess.check_output([str(git), "-C", str(repository), "ls-tree", "-r", "-z", COMMIT], timeout=120)
    expected = {}
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        fields, name = entry.split(b"\t", 1)
        mode, kind, blob = fields.decode().split()
        name = name.decode()
        parts = Path(name).parts
        if kind != "blob" or mode not in {"100644", "100755", "120000"} or ".git" in parts:
            raise ValueError("capture contains an unsupported Git entry")
        expected[name] = (mode, blob)
    source = output / "source"
    source.mkdir(mode=0o700)
    census = []
    with tarfile.open(archive) as bundle:
        for member in bundle:
            relative = Path(member.name)
            if relative.is_absolute() or any(part in {"..", ".git"} for part in relative.parts):
                raise ValueError("archive entry leaves selected source")
            path = source / relative
            if member.isdir():
                path.mkdir(exist_ok=True)
                continue
            mode, blob = expected.pop(member.name)
            if any(parent.is_symlink() for parent in path.parents if parent != source.parent):
                raise ValueError("archive parent is a link")
            if mode == "120000":
                if not member.issym():
                    raise ValueError("archive symlink kind differs")
                raw = member.linkname.encode()
                path.symlink_to(member.linkname)
            else:
                if not member.isfile():
                    raise ValueError("archive regular kind differs")
                raw = bundle.extractfile(member).read()
                with path.open("xb") as stream:
                    stream.write(raw)
                path.chmod(0o755 if mode == "100755" else 0o644)
            actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if actual_blob != blob:
                raise ValueError("archive bytes differ from selected Git blob")
            census.append({"path":member.name,"mode":mode,"gitBlob":blob,
                "sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)})
    if expected:
        raise ValueError("archive omitted committed entries")
    census.sort(key=lambda row:row["path"])
    receipt = {"version":1,"commit":COMMIT,"git":str(git),"gitSha256":git_sha256,
        "archiveSha256":hashlib.sha256(archive.read_bytes()).hexdigest(),
        "sourceEntries":len(census),"workingTreeOverlay":False,"census":census}
    with (output / "receipt.json").open("x") as stream:
        json.dump(receipt,stream,indent=2)
        stream.write("\n")
    return receipt
