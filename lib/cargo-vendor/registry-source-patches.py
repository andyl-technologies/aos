"""Applies bounded, exact-identity patches to already assembled registry sources.

The input is a normalized JSON list of records with ``source``, ``name``,
``version``, ``archiveSha256``, ``patch``, ``patchSha256`` and ``files``. Each
file has ``path``, ``beforeSha256`` and ``afterSha256``. The existing staging
archive and Cargo.lock remain unchanged. Only the explicitly selected existing
files may change; the fixed source-built patch tool owns patch application.

The output receipt is unsigned source-provenance DATA, never runtime authority.
An empty recipe performs no reads, writes or subprocess invocation below.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tomllib
from pathlib import Path


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = ".cargo-checksum.json"
RECEIPT = ".aos-registry-source-patches.json"
MAXIMUM_RECIPE_BYTES = 1024 * 1024
MAXIMUM_PATCH_BYTES = 8 * 1024 * 1024
MAXIMUM_FILE_BYTES = 64 * 1024 * 1024
MAXIMUM_TREE_BYTES = 512 * 1024 * 1024
MAXIMUM_FILES = 16384
MAXIMUM_DIRECTORIES = 4096
MAXIMUM_RECORDS = 64
COMPONENT = re.compile(r"[A-Za-z0-9._+-]{1,256}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HUNK = re.compile(rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: [^\r\n]*)?\n\Z")
INDEX = re.compile(rb"index [0-9a-f]{4,64}\.\.[0-9a-f]{4,64}(?: (100644|100755))?\n\Z")


class PatchContractError(ValueError):
    """Reports a fixed source-delivery contract failure without fallback."""


def require(condition, message):
    if not condition:
        raise PatchContractError(message)


def exact_keys(value, keys, subject):
    require(isinstance(value, dict) and set(value) == set(keys), subject + " schema differs")


def digest(value):
    require(isinstance(value, str) and SHA256.fullmatch(value), "invalid SHA256")
    require(value != "0" * 64, "zero SHA256 is not a source identity")
    return value


def component(value):
    require(isinstance(value, str) and COMPONENT.fullmatch(value), "unsafe identity component")
    require(value not in (".", ".."), "unsafe identity component")
    return value


def relative_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024, "invalid relative path")
    require(not any(character in value for character in ("\\", "\0")), "unsafe relative path")
    require(not value.startswith("/"), "absolute patch path")
    parts = value.split("/")
    for part in parts:
        component(part)
    return value


def require_directory(path):
    """Rejects symlink parents before inspecting a selected tree or input."""
    require(path.is_absolute(), "input root must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        require(part not in (".", ".."), "unsafe input root")
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), "non-directory or symlink parent")


def regular_file(path, maximum):
    """Checks bounded immutable inputs without rejecting store optimization."""
    require_directory(path.parent)
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), "non-regular source file")
    require(metadata.st_size <= maximum, "source file exceeds bound")
    return metadata


def mutable_file(path, maximum):
    """Requires an unshared inode before inspecting the writable vendor tree."""
    metadata = regular_file(path, maximum)
    require(metadata.st_nlink == 1, "hardlinked source file")
    return metadata


def file_hash(path, maximum=MAXIMUM_FILE_BYTES):
    regular_file(path, maximum)
    result = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            consumed += len(chunk)
            require(consumed <= maximum, "source file exceeds bound")
            result.update(chunk)
    return result.hexdigest()


def unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def load_json(path, maximum):
    regular_file(path, maximum)
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    require(len(data) <= maximum, "JSON exceeds bound")
    return json.loads(data, object_pairs_hook=unique_json_object)


def validate_recipe(records):
    require(
        isinstance(records, list) and len(records) <= MAXIMUM_RECORDS,
        "recipe list exceeds bound",
    )
    identities = set()
    for record in records:
        exact_keys(
            record,
            (
                "source",
                "name",
                "version",
                "archiveSha256",
                "patch",
                "patchSha256",
                "files",
            ),
            "recipe",
        )
        require(record["source"] == REGISTRY, "unsupported registry source")
        identity = (
            record["source"],
            component(record["name"]),
            component(record["version"]),
        )
        require(
            record["name"][0].isalnum() and record["version"][0].isalnum(),
            "unsafe package identity",
        )
        require(identity not in identities, "duplicate selected package")
        identities.add(identity)
        digest(record["archiveSha256"])
        digest(record["patchSha256"])
        require(
            isinstance(record["patch"], str) and Path(record["patch"]).is_absolute(),
            "patch must be an absolute source path",
        )

        files = record["files"]
        require(
            isinstance(files, list) and 0 < len(files) <= MAXIMUM_FILES,
            "invalid selected file list",
        )
        paths = []
        for selected in files:
            exact_keys(selected, ("path", "beforeSha256", "afterSha256"), "selected file")
            path = relative_path(selected["path"])
            require(
                Path(path).name not in ("Cargo.toml", "Cargo.lock", CHECKSUM),
                "manifest or checksum patch refused",
            )
            require(not path.startswith(".cargo/"), "Cargo configuration patch refused")
            digest(selected["beforeSha256"])
            digest(selected["afterSha256"])
            require(selected["beforeSha256"] != selected["afterSha256"], "no-op selected file")
            paths.append(path)
        require(paths == sorted(set(paths)), "selected paths must be unique and sorted")
    require(
        records == sorted(
            records,
            key=lambda record: (record["source"], record["name"], record["version"]),
        ),
        "recipe must be sorted",
    )


def tree_snapshot(root):
    """Returns bounded regular-file identities and all original directory modes."""
    require_directory(root)
    files = {}
    directories = {"": stat.S_IMODE(root.lstat().st_mode)}
    total = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        names.sort()
        filenames.sort()
        parent = Path(directory)
        for name in names:
            path = parent / name
            relative = relative_path(path.relative_to(root).as_posix())
            metadata = path.lstat()
            require(stat.S_ISDIR(metadata.st_mode), "symlink or non-directory in crate")
            directories[relative] = stat.S_IMODE(metadata.st_mode)
            require(len(directories) <= MAXIMUM_DIRECTORIES, "crate directory limit")
        for name in filenames:
            path = parent / name
            relative = relative_path(path.relative_to(root).as_posix())
            metadata = mutable_file(path, MAXIMUM_FILE_BYTES)
            total += metadata.st_size
            require(total <= MAXIMUM_TREE_BYTES, "crate byte limit")
            files[relative] = (file_hash(path), stat.S_IMODE(metadata.st_mode))
            require(len(files) <= MAXIMUM_FILES, "crate file limit")
    return files, directories


def archive_snapshot(archive, crate_name):
    """Checks original archive contents without re-extracting or rewriting them."""
    files = {}
    seen = set()
    total = 0
    with tarfile.open(archive, mode="r:gz") as source:
        for entry in source:
            name = entry.name.rstrip("/") if entry.isdir() else entry.name
            relative_path(name)
            require(name == crate_name or name.startswith(crate_name + "/"), "archive root differs")
            require(name not in seen, "duplicate archive member")
            seen.add(name)
            require(len(seen) <= MAXIMUM_FILES + MAXIMUM_DIRECTORIES, "archive member limit")
            require(entry.isdir() or entry.isfile(), "archive link or special file refused")
            if entry.isdir():
                continue
            relative = name[len(crate_name) + 1:]
            relative_path(relative)
            require(relative != CHECKSUM, "archive supplied vendor checksum")
            require(0 <= entry.size <= MAXIMUM_FILE_BYTES, "archive file limit")
            total += entry.size
            require(total <= MAXIMUM_TREE_BYTES, "archive byte limit")
            reader = source.extractfile(entry)
            require(reader is not None, "archive file unavailable")
            result = hashlib.sha256()
            remaining = entry.size
            with reader:
                while remaining:
                    chunk = reader.read(min(64 * 1024, remaining))
                    require(chunk, "truncated archive member")
                    result.update(chunk)
                    remaining -= len(chunk)
            files[relative] = result.hexdigest()
    return files


def selected_crate(staging, vendor, record, lock):
    identity = (record["source"], record["name"], record["version"])
    rows = [
        row
        for row in lock.get("package", [])
        if (row.get("source"), row.get("name"), row.get("version")) == identity
    ]
    require(len(rows) == 1, "missing or ambiguous locked package")
    require(rows[0].get("checksum") == record["archiveSha256"], "lock archive checksum differs")

    crate_name = record["name"] + "-" + record["version"]
    archive = staging / "tarballs" / (crate_name + ".tar.gz")
    require(
        file_hash(archive, MAXIMUM_TREE_BYTES) == record["archiveSha256"],
        "staging archive checksum differs",
    )
    root = vendor / "source-registry-0" / crate_name
    before, directories = tree_snapshot(root)
    original = archive_snapshot(archive, crate_name)
    require(
        {path: value[0] for path, value in before.items() if path != CHECKSUM} == original,
        "assembled crate differs from original archive",
    )
    require(CHECKSUM in before, "original vendor checksum missing")
    require(
        load_json(root / CHECKSUM, MAXIMUM_RECIPE_BYTES) == {
            "files": {},
            "package": record["archiveSha256"],
        },
        "original vendor checksum differs",
    )

    with (root / "Cargo.toml").open("rb") as source:
        manifest = tomllib.load(source)
    require(
        manifest.get("package", {}).get("name") == record["name"],
        "crate manifest name differs",
    )
    require(
        manifest.get("package", {}).get("version") == record["version"],
        "crate manifest version differs",
    )
    for selected in record["files"]:
        require(selected["path"] in before, "selected file does not exist")
        require(
            before[selected["path"]][0] == selected["beforeSha256"],
            "selected before checksum differs",
        )
    return root, before, directories


def split_lf_lines(data):
    """Retains exact byte lines, including an optional unterminated final line."""
    parts = data.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def check_unified_patch(data, root, record, before):
    """Validates exact old hunk coordinates; the fixed patch tool applies bytes."""
    require(
        data and data.endswith(b"\n") and b"\0" not in data and b"\r" not in data,
        "patch is not canonical unified text",
    )
    lines = split_lf_lines(data)
    index = 0
    selected = {item["path"] for item in record["files"]}
    changed = set()
    while index < len(lines):
        git_path = None
        if lines[index].startswith(b"diff --git "):
            fields = lines[index].removesuffix(b"\n").split(b" ")
            require(
                len(fields) == 4 and fields[:2] == [b"diff", b"--git"],
                "unexpected Git patch header",
            )
            git_path = fields[2][2:].decode("ascii")
            require(
                fields[2] == b"a/" + git_path.encode()
                and fields[3] == b"b/" + git_path.encode(),
                "rename or unsafe Git header",
            )
            index += 1
            if index < len(lines) and lines[index].startswith(b"index "):
                match = INDEX.fullmatch(lines[index])
                require(match is not None, "unexpected mode or index header")
                if match[1] is not None:
                    require(git_path in before, "Git header file absent")
                    expected_mode = b"100755" if before[git_path][1] & 0o111 else b"100644"
                    require(match[1] == expected_mode, "Git file mode differs")
                index += 1

        require(
            index + 1 < len(lines)
            and lines[index].startswith(b"--- a/")
            and lines[index + 1].startswith(b"+++ b/"),
            "non-unified, create/delete or extra patch header",
        )
        path = lines[index][6:].removesuffix(b"\n").decode("ascii")
        relative_path(path)
        require(
            lines[index + 1] == b"+++ b/" + path.encode() + b"\n",
            "rename, timestamp or path mismatch",
        )
        require(git_path is None or git_path == path, "Git and unified headers differ")
        require(path in selected and path not in changed, "extra or repeated patched file")
        changed.add(path)
        index += 2

        original_lines = split_lf_lines((root / path).read_bytes())
        previous_end = 0
        delta = 0
        hunks = 0
        while index < len(lines) and lines[index].startswith(b"@@ "):
            header = HUNK.fullmatch(lines[index])
            require(header is not None, "invalid unified hunk")
            old_start, old_count = int(header[1]), int(header[2] or b"1")
            new_start, new_count = int(header[3]), int(header[4] or b"1")
            old_offset = old_start - 1 if old_count else old_start
            new_offset = new_start - 1 if new_count else new_start
            require(
                old_offset >= previous_end and new_offset == old_offset + delta,
                "overlap or hunk coordinate offset",
            )
            index += 1
            old_lines = []
            added = 0
            while len(old_lines) < old_count or added < new_count:
                require(
                    index < len(lines) and lines[index][:1] in (b" ", b"+", b"-"),
                    "invalid unified payload",
                )
                line = lines[index]
                index += 1
                value = line[1:]
                if index < len(lines) and lines[index] == b"\\ No newline at end of file\n":
                    value = value.removesuffix(b"\n")
                    index += 1
                if line[:1] in (b" ", b"-"):
                    old_lines.append(value)
                if line[:1] in (b" ", b"+"):
                    added += 1
                require(
                    len(old_lines) <= old_count and added <= new_count,
                    "hunk line counts differ",
                )

            require(
                old_offset <= len(original_lines)
                and original_lines[old_offset:old_offset + old_count] == old_lines,
                "hunk would require offset or fuzz",
            )
            previous_end = old_offset + old_count
            delta += new_count - old_count
            hunks += 1
        require(hunks, "patched file omitted hunks")
    require(changed == selected, "patch omitted selected file")


def apply_record(root, before, directories, record, patch_tool):
    patch = Path(record["patch"])
    require(
        file_hash(patch, MAXIMUM_PATCH_BYTES) == record["patchSha256"],
        "patch checksum differs",
    )
    check_unified_patch(patch.read_bytes(), root, record, before)

    result = subprocess.run(
        [
            str(patch_tool),
            "--batch",
            "--forward",
            "--fuzz=0",
            "--no-backup-if-mismatch",
            "-p1",
            "--input",
            str(patch),
        ],
        cwd=root,
        env={"LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(result.returncode == 0, "fixed patch tool failed; no fallback")
    require(
        not re.search(rb"offset|fuzz", result.stdout + result.stderr, re.IGNORECASE),
        "patch reported offset or fuzz",
    )

    after, after_directories = tree_snapshot(root)
    require(
        after.keys() == before.keys() and after_directories == directories,
        "patch changed tree paths or directory modes",
    )
    targets = {item["path"]: item["afterSha256"] for item in record["files"]}
    for path, (checksum, mode) in after.items():
        require(mode == before[path][1], "patch changed file mode")
        require(
            checksum == targets.get(path, before[path][0]),
            "unexpected patched or unselected content",
        )

    checksums = {
        "files": {path: after[path][0] for path in sorted(after) if path != CHECKSUM},
        "package": record["archiveSha256"],
    }
    (root / CHECKSUM).write_text(
        json.dumps(checksums, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def apply_patches(staging, vendor, records, patch_tool):
    """Applies a nonempty normalized recipe or leaves an empty output untouched.

    Raises PatchContractError on contract mismatch, and preserves concrete IO,
    JSON/TOML/archive or subprocess setup causes. Any error aborts the builder;
    a partially transformed output is never a usable successful derivation.
    """
    validate_recipe(records)
    if not records:
        return

    require_directory(staging)
    require_directory(vendor)
    require(
        not (vendor / RECEIPT).exists() and not (vendor / RECEIPT).is_symlink(),
        "patch receipt already exists",
    )
    require(
        patch_tool.is_absolute() and patch_tool.name == "patch",
        "fixed absolute patch executable required",
    )
    metadata = regular_file(patch_tool, MAXIMUM_FILE_BYTES)
    require(metadata.st_mode & 0o111, "patch tool is not executable")
    regular_file(staging / "Cargo.lock", 16 * 1024 * 1024)
    mutable_file(vendor / "Cargo.lock", 16 * 1024 * 1024)
    require(
        file_hash(staging / "Cargo.lock") == file_hash(vendor / "Cargo.lock"),
        "staging and vendor lock differ",
    )
    with (staging / "Cargo.lock").open("rb") as source:
        lock = tomllib.load(source)

    prepared = [(*selected_crate(staging, vendor, record, lock), record) for record in records]
    for root, before, directories, record in prepared:
        apply_record(root, before, directories, record, patch_tool)

    receipt = {"schema": "aos.registry-source-patches/v1", "patches": records}
    (vendor / RECEIPT).write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--vendor", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--patch-tool", type=Path, required=True)
    arguments = parser.parse_args()
    records = load_json(arguments.recipe, MAXIMUM_RECIPE_BYTES)
    apply_patches(arguments.staging, arguments.vendor, records, arguments.patch_tool)


if __name__ == "__main__":
    main()
