"""Checks logical contents and FAT allocation using the production ESP helper."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
for name in ["bash", "helper", "mkfs", "mcopy", "mshowfat", "tool-path"]:
    parser.add_argument("--" + name, required=True)
args = parser.parse_args()

with tempfile.TemporaryDirectory(prefix="esp-population-") as directory:
    temporary = Path(directory)
    environment = {
        "PATH": args.tool_path,
        "TMPDIR": str(temporary),
        "LC_ALL": "C",
        "MTOOLS_SKIP_CHECK": "1",
    }

    def run(arguments, success=True):
        result = subprocess.run(arguments, env=environment, capture_output=True)
        assert (result.returncode == 0) == success, (arguments, result.stderr)
        return result.stdout

    payloads = {
        "EFI/Linux/largest image.efi": b"large payload\n" * 16384,
        "EFI/Boot/boot.efi": b"boot payload\n" * 4096,
        "loader/entries/tie a.conf": b"same size A\n",
        "loader/entries/tie b.conf": b"same size B\n",
        "loader/.hidden config": b"hidden content\n",
        "alias payload": b"retained alias bytes\n",
    }
    external = temporary / "retained artifact"
    external.write_bytes(payloads["alias payload"])
    allocation = []
    for index, names in enumerate([list(payloads), list(reversed(payloads))]):
        source = temporary / f"source-{index}"
        source.mkdir()
        (source / "empty dir/subdirectory").mkdir(parents=True)
        for name in names:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name == "alias payload":
                path.symlink_to(external)
            else:
                path.write_bytes(payloads[name])
            os.utime(path, (1577836800, 1577836800))

        image = temporary / f"esp-{index}.img"
        with image.open("wb") as output:
            output.truncate(16 * 1024 * 1024)
        run([args.mkfs, "--invariant", "-F", "16", str(image)])
        run([args.bash, args.helper, str(source), str(image)])
        extracted = temporary / f"extracted-{index}"
        extracted.mkdir()
        run([args.mcopy, "-s", "-i", str(image), "::/*", str(extracted)])
        actual = {
            str(path.relative_to(extracted)): path.read_bytes()
            for path in extracted.rglob("*") if path.is_file()
        }
        assert actual == payloads, actual.keys()
        assert (extracted / "empty dir/subdirectory").is_dir()
        allocation.append({
            name: re.findall(rb"<[^>]*>", run([args.mshowfat, "-i", str(image), "::/" + name]))
            for name in payloads
        })
        assert all(allocation[-1].values())
        assert (source / "alias payload").is_symlink()
        assert external.read_bytes() == payloads["alias payload"]

    # Timestamps need not match; physical file cluster assignments must not
    # depend on source directory insertion order, including equal-size ties.
    assert allocation[0] == allocation[1], allocation
    protected_image = temporary / "esp-0.img"
    original_image_hash = hashlib.sha256(protected_image.read_bytes()).digest()
    for invalid in ["dangling", "special", "loop"]:
        source = temporary / invalid
        source.mkdir()
        if invalid == "dangling":
            (source / "missing").symlink_to(source / "absent")
        elif invalid == "special":
            os.mkfifo(source / "fifo")
        else:
            (source / "cycle").symlink_to(source)
        run([args.bash, args.helper, str(source), str(protected_image)], success=False)
        assert hashlib.sha256(protected_image.read_bytes()).digest() == original_image_hash

print("PASS: exact FAT contents, deterministic allocation, aliases, and invalid-source refusal")
