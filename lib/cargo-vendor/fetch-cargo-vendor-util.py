#!/usr/bin/env python3
"""Cargo dependency vendoring utility.

Port of nixpkgs's fetch-cargo-vendor-util-v2.py, adapted for AOS to use only
the Python standard library (no `requests`, no `tomli_w`) and a direct
`git clone` instead of `nix-prefetch-git`.

Two subcommands:

* create-vendor-staging <Cargo.lock> <out_dir>
    Network-facing. Run inside a fixed-output derivation. Downloads every
    crates.io tarball into <out_dir>/tarballs/ and clones every git source
    at its exact rev into <out_dir>/git/<sha>/. Also copies the lockfile.

* create-vendor <staging_dir> <out_dir>
    Pure. Reads <staging_dir>/Cargo.lock, extracts crates.io tarballs into
    per-source vendor subdirs, locates each git-sourced crate's manifest by
    name via `cargo metadata --no-deps`, copies the crate's subtree out,
    runs replace-workspace-values for workspace inheritance, and writes
    .cargo/config.toml with the source replacement table.

The final vendor output uses @vendor@ as a placeholder for the absolute
vendor directory path in `.cargo/config.toml`; the cargoPhases build phase
substitutes the real path before invoking cargo.
"""

import functools
import hashlib
import json
import multiprocessing as mp
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
import urllib.error
from os.path import islink, realpath
from pathlib import Path
from typing import Any, TypedDict, cast
from urllib.parse import unquote

eprint = functools.partial(print, file=sys.stderr)


# ---------------------------------------------------------------------------
# Minimal TOML writer
# ---------------------------------------------------------------------------
# Cargo only needs valid TOML, not formatting-preserving output. We serialize
# the dict structures returned by tomllib back to TOML. Handles strings,
# bools, ints, floats, datetimes (as their repr), lists (as inline arrays),
# nested tables (emitted as [a.b.c] section headers when all entries are
# tables, inline {x = y} otherwise), and arrays of tables ([[a.b]]).

_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _toml_escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _toml_key(k: str) -> str:
    if _BARE_KEY_RE.match(k):
        return k
    return _toml_escape_string(k)


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return _toml_escape_string(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return (
            "{ "
            + ", ".join(f"{_toml_key(k)} = {_toml_value(val)}" for k, val in v.items())
            + " }"
        )
    # Fallback for datetimes etc. — tomllib returns datetime objects, but Cargo
    # manifests rarely contain them. Serialize as RFC3339 ISO repr.
    return _toml_escape_string(str(v))


def _is_table(v: Any) -> bool:
    return isinstance(v, dict)


def _array_of_tables(v: Any) -> bool:
    return isinstance(v, list) and len(v) > 0 and all(isinstance(x, dict) for x in v)


def _emit_table(buf: list[str], data: dict, header: list[str]) -> None:
    # Inline keys first (non-table values), then nested tables, then arrays of tables.
    inline_keys = []
    table_keys = []
    aot_keys = []
    for k, v in data.items():
        if _array_of_tables(v):
            aot_keys.append(k)
        elif _is_table(v):
            table_keys.append(k)
        else:
            inline_keys.append(k)

    if header and (inline_keys or not (table_keys or aot_keys)):
        buf.append(f"[{'.'.join(_toml_key(p) for p in header)}]")

    for k in inline_keys:
        buf.append(f"{_toml_key(k)} = {_toml_value(data[k])}")

    if inline_keys and (table_keys or aot_keys):
        buf.append("")

    for k in table_keys:
        if buf and buf[-1] != "":
            buf.append("")
        _emit_table(buf, data[k], header + [k])

    for k in aot_keys:
        for entry in data[k]:
            if buf and buf[-1] != "":
                buf.append("")
            buf.append(f"[[{'.'.join(_toml_key(p) for p in (header + [k]))}]]")
            # Emit entry contents; if entry has no inline keys but has nested
            # tables, the header above is enough.
            sub_header = header + [k]
            sub_inline = [(kk, vv) for kk, vv in entry.items() if not _is_table(vv) and not _array_of_tables(vv)]
            sub_tables = [(kk, vv) for kk, vv in entry.items() if _is_table(vv)]
            sub_aots = [(kk, vv) for kk, vv in entry.items() if _array_of_tables(vv)]
            for kk, vv in sub_inline:
                buf.append(f"{_toml_key(kk)} = {_toml_value(vv)}")
            for kk, vv in sub_tables:
                if buf and buf[-1] != "":
                    buf.append("")
                _emit_table(buf, vv, sub_header + [kk])
            for kk, vv in sub_aots:
                for sub_entry in vv:
                    if buf and buf[-1] != "":
                        buf.append("")
                    buf.append(f"[[{'.'.join(_toml_key(p) for p in (sub_header + [kk]))}]]")
                    _emit_table(buf, sub_entry, sub_header + [kk])


def toml_dumps(data: dict) -> str:
    buf: list[str] = []
    _emit_table(buf, data, [])
    if not buf or buf[-1] != "":
        buf.append("")
    return "\n".join(buf)


def toml_dump(data: dict, fp) -> None:
    fp.write(toml_dumps(data).encode("utf-8"))


# ---------------------------------------------------------------------------
# Cargo.lock parsing
# ---------------------------------------------------------------------------


def load_toml(path: Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def get_lockfile_version(cargo_lock_toml: dict[str, Any]) -> int:
    return cargo_lock_toml.get("version", 2)


GIT_SOURCE_REGEX = re.compile(
    r"git\+(?P<url>[^?]+)(\?(?P<type>rev|tag|branch)=(?P<value>.*))?#(?P<git_sha_rev>.*)"
)


class GitSourceInfo(TypedDict):
    url: str
    type: str | None
    value: str | None
    git_sha_rev: str


def parse_git_source(source: str, lockfile_version: int) -> GitSourceInfo:
    match = GIT_SOURCE_REGEX.match(source)
    if match is None:
        raise Exception(f"Unable to process git source: {source}.")

    source_info = cast(GitSourceInfo, match.groupdict(default=None))

    if lockfile_version >= 4 and source_info["value"] is not None:
        source_info["value"] = unquote(source_info["value"])

    return source_info


# ---------------------------------------------------------------------------
# Stage 1: download tarballs + clone git trees
# ---------------------------------------------------------------------------


def download_file_with_checksum(url: str, destination_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "aos-fetchCargoVendor/1 (https://andyl.com)"},
    )
    # Retry transient HTTP failures
    last_exc = None
    for attempt in range(5):
        try:
            # A half-open TCP/TLS connection can otherwise wedge a fixed-output
            # build forever. Each attempt is independently reproducible, so
            # bound stalled I/O and let the existing retry loop reconnect.
            with urllib.request.urlopen(req, timeout=60) as response:
                if response.status >= 400:
                    raise Exception(
                        f"Failed to fetch file from {url}. Status code: {response.status}"
                    )
                with open(destination_path, "wb") as f:
                    while True:
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            ConnectionError,
            TimeoutError,
        ) as e:
            last_exc = e
            eprint(f"Fetch attempt {attempt + 1} for {url} failed: {e}; retrying...")
            sha256_hash = hashlib.sha256()
    raise Exception(f"Failed to fetch {url} after 5 attempts: {last_exc}")


def get_download_url_for_tarball(pkg: dict[str, Any]) -> str:
    if pkg["source"] != "registry+https://github.com/rust-lang/crates.io-index":
        raise Exception("Only the default crates.io registry is supported.")
    return f"https://static.crates.io/crates/{pkg['name']}/{pkg['version']}/download"


def download_tarball(pkg: dict[str, Any], out_dir: Path) -> None:
    url = get_download_url_for_tarball(pkg)
    filename = f"{pkg['name']}-{pkg['version']}.tar.gz"
    expected_checksum = pkg.get("checksum")
    tarball_out_path = out_dir / "tarballs" / filename
    eprint(f"Fetching {url} -> tarballs/{filename}")
    calculated = download_file_with_checksum(url, tarball_out_path)
    # Some lockfile entries omit `checksum` (e.g. when a [patch] override is
    # in play). Cargo allows this; we mirror the behavior and skip the
    # verification step. The enclosing FOD's content hash still pins the
    # exact bytes we downloaded.
    if expected_checksum is not None and calculated != expected_checksum:
        raise Exception(
            f"Hash mismatch! {url} got {calculated}, expected {expected_checksum}."
        )


def download_git_tree(url: str, git_sha_rev: str, out_dir: Path) -> None:
    tree_out_dir = out_dir / "git" / git_sha_rev
    eprint(f"Cloning {url}#{git_sha_rev} -> git/{git_sha_rev}")
    tree_out_dir.parent.mkdir(parents=True, exist_ok=True)
    # Full clone to ensure the rev is reachable; shallow clones of arbitrary
    # SHAs require server-side allowAnyOID, which isn't universal.
    subprocess.check_call(
        ["git", "clone", "--quiet", url, str(tree_out_dir)],
        env={**os.environ},
    )
    subprocess.check_call(
        ["git", "-C", str(tree_out_dir), "checkout", "--quiet", git_sha_rev]
    )
    if (tree_out_dir / ".gitmodules").exists():
        subprocess.check_call(
            [
                "git",
                "-C",
                str(tree_out_dir),
                "submodule",
                "update",
                "--init",
                "--recursive",
            ]
        )
    shutil.rmtree(tree_out_dir / ".git", ignore_errors=True)


def create_vendor_staging(lockfile_path: Path, out_dir: Path) -> None:
    cargo_lock_toml = load_toml(lockfile_path)
    lockfile_version = get_lockfile_version(cargo_lock_toml)

    git_packages: list[dict[str, Any]] = []
    registry_packages: list[dict[str, Any]] = []

    for pkg in cargo_lock_toml["package"]:
        if "source" not in pkg.keys():
            eprint(f"Skipping local dependency: {pkg['name']}")
            continue
        source = pkg["source"]
        if source.startswith("git+"):
            git_packages.append(pkg)
        elif source.startswith("registry+"):
            registry_packages.append(pkg)
        else:
            raise Exception(f"Can't process source: {source}.")

    git_sha_rev_to_url: dict[str, str] = {}
    for pkg in git_packages:
        source_info = parse_git_source(pkg["source"], lockfile_version)
        git_sha_rev_to_url[source_info["git_sha_rev"]] = source_info["url"]

    out_dir.mkdir(exist_ok=True)
    shutil.copy(lockfile_path, out_dir / "Cargo.lock")

    if len(git_packages) != 0:
        (out_dir / "git").mkdir(exist_ok=True)
        for git_sha_rev, url in git_sha_rev_to_url.items():
            download_git_tree(url, git_sha_rev, out_dir)

    if len(registry_packages) != 0:
        (out_dir / "tarballs").mkdir(exist_ok=True)
        with mp.Pool(min(5, mp.cpu_count())) as pool:
            pool.starmap(download_tarball, ((pkg, out_dir) for pkg in registry_packages))


# ---------------------------------------------------------------------------
# Stage 2: assemble vendor directory + .cargo/config.toml
# ---------------------------------------------------------------------------


def get_manifest_metadata(manifest_path: Path) -> dict[str, Any]:
    cmd = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--manifest-path",
        str(manifest_path),
    ]
    output = subprocess.check_output(cmd)
    return json.loads(output)


def try_get_crate_manifest_path_from_manifest_path(
    manifest_path: Path, crate_name: str
) -> Path | None:
    try:
        metadata = get_manifest_metadata(manifest_path)
    except subprocess.CalledProcessError:
        eprint(f"Warning: cargo metadata failed for {manifest_path}, skipping")
        return None
    for pkg in metadata["packages"]:
        if pkg["name"] == crate_name:
            return Path(pkg["manifest_path"])
    return None


def find_crate_manifest_in_tree(tree: Path, crate_name: str) -> Path:
    manifest_paths = sorted(
        tree.glob("**/Cargo.toml"),
        key=lambda path: (len(path.parts), str(path)),
    )
    for manifest_path in manifest_paths:
        res = try_get_crate_manifest_path_from_manifest_path(manifest_path, crate_name)
        if res is not None:
            return res
    raise Exception(f"Couldn't find manifest for crate {crate_name} inside {tree}.")


def copy_and_patch_git_crate_subtree(
    git_tree: Path, crate_name: str, crate_out_dir: Path
) -> None:
    def ignore_func(dir_str: str, path_strs: list[str]) -> list[str]:
        ignorelist: list[str] = []
        dir = Path(realpath(dir_str, strict=True))
        for path_str in path_strs:
            path = dir / path_str
            if not islink(path):
                continue
            try:
                target_path = Path(realpath(path, strict=True))
            except OSError:
                ignorelist.append(path_str)
                eprint(f"Failed to resolve symlink, ignoring: {path}")
                continue
            if not target_path.is_relative_to(git_tree):
                ignorelist.append(path_str)
                eprint(
                    f"Symlink points outside of the crate's base git tree, ignoring:"
                    f" {path} -> {target_path}"
                )
                continue
        return ignorelist

    crate_manifest_path = find_crate_manifest_in_tree(git_tree, crate_name)
    crate_tree = crate_manifest_path.parent

    eprint(f"Copying to {crate_out_dir}")
    shutil.copytree(crate_tree, crate_out_dir, ignore=ignore_func)
    crate_out_dir.chmod(0o755)

    with open(crate_manifest_path, "r") as f:
        manifest_data = f.read()

    if "workspace" in manifest_data:
        crate_manifest_metadata = get_manifest_metadata(crate_manifest_path)
        workspace_root = Path(crate_manifest_metadata["workspace_root"])
        root_manifest_path = workspace_root / "Cargo.toml"
        manifest_path = crate_out_dir / "Cargo.toml"
        manifest_path.chmod(0o644)
        eprint(f"Patching {manifest_path}")
        script_dir = Path(__file__).resolve().parent
        subprocess.check_call(
            [
                sys.executable,
                str(script_dir / "replace-workspace-values.py"),
                str(manifest_path),
                str(root_manifest_path),
            ]
        )


def extract_crate_tarball_contents(tarball_path: Path, crate_out_dir: Path) -> None:
    eprint(f"Unpacking to {crate_out_dir}")
    crate_out_dir.mkdir()
    subprocess.check_call(
        ["tar", "xf", str(tarball_path), "-C", str(crate_out_dir), "--strip-components=1"]
    )


def make_git_source_selector(source_info: GitSourceInfo) -> dict[str, str]:
    selector: dict[str, str] = {"git": source_info["url"]}
    if source_info["type"] is not None:
        selector[source_info["type"]] = source_info["value"]  # type: ignore[assignment]
    return selector


def make_registry_source_selector(source: str) -> dict[str, str]:
    registry = source[9:] if source.startswith("registry+") else source
    return {"registry": registry}


def create_vendor(vendor_staging_dir: Path, out_dir: Path) -> None:
    lockfile_path = vendor_staging_dir / "Cargo.lock"
    out_dir.mkdir(exist_ok=True)
    shutil.copy(lockfile_path, out_dir / "Cargo.lock")

    cargo_lock_toml = load_toml(lockfile_path)
    lockfile_version = get_lockfile_version(cargo_lock_toml)

    source_to_ind: dict[str, str] = {}
    source_config: dict[str, dict[str, str]] = {}
    next_registry_ind = 0
    next_git_ind = 0

    def add_source_replacement(
        orig_key: str,
        orig_selector: dict[str, str],
        vendored_key: str,
        vendored_dir: str,
    ) -> None:
        source_config[vendored_key] = {"directory": vendored_dir}
        entry = dict(orig_selector)
        entry["replace-with"] = vendored_key
        source_config[orig_key] = entry

    # Reserve registry index 0 for crates-io
    source_to_ind["registry+https://github.com/rust-lang/crates.io-index"] = "registry-0"
    source_to_ind["sparse+https://index.crates.io/"] = "registry-0"
    add_source_replacement(
        orig_key="crates-io",
        orig_selector={},
        vendored_key="vendored-source-registry-0",
        vendored_dir="@vendor@/source-registry-0",
    )
    next_registry_ind += 1

    for pkg in cargo_lock_toml["package"]:
        if "source" not in pkg.keys():
            continue
        source: str = pkg["source"]
        if source in source_to_ind:
            continue
        if source.startswith("git+"):
            ind = f"git-{next_git_ind}"
            next_git_ind += 1
            source_info = parse_git_source(source, lockfile_version)
            selector = make_git_source_selector(source_info)
        elif source.startswith("registry+") or source.startswith("sparse+"):
            ind = f"registry-{next_registry_ind}"
            next_registry_ind += 1
            selector = make_registry_source_selector(source)
        else:
            raise Exception(f"Can't process source: {source}.")
        source_to_ind[source] = ind
        add_source_replacement(
            orig_key=f"original-source-{ind}",
            orig_selector=selector,
            vendored_key=f"vendored-source-{ind}",
            vendored_dir=f"@vendor@/source-{ind}",
        )

    config_path = out_dir / ".cargo" / "config.toml"
    config_path.parent.mkdir()
    with open(config_path, "wb") as f:
        toml_dump({"source": source_config}, f)

    for pkg in cargo_lock_toml["package"]:
        if "source" not in pkg.keys():
            continue
        source = pkg["source"]
        source_ind = source_to_ind[source]
        crate_dir_name = f"{pkg['name']}-{pkg['version']}"
        source_dir_name = f"source-{source_ind}"
        crate_out_dir = out_dir / source_dir_name / crate_dir_name
        crate_out_dir.parent.mkdir(exist_ok=True)

        if source.startswith("git+"):
            source_info = parse_git_source(source, lockfile_version)
            git_sha_rev = source_info["git_sha_rev"]
            git_tree = vendor_staging_dir / "git" / git_sha_rev
            copy_and_patch_git_crate_subtree(git_tree, pkg["name"], crate_out_dir)
            with open(crate_out_dir / ".cargo-checksum.json", "w") as f:
                json.dump({"files": {}}, f)
        elif source.startswith("registry+") or source.startswith("sparse+"):
            filename = f"{pkg['name']}-{pkg['version']}.tar.gz"
            tarball_path = vendor_staging_dir / "tarballs" / filename
            extract_crate_tarball_contents(tarball_path, crate_out_dir)
            checksum_obj: dict[str, Any] = {"files": {}}
            if "checksum" in pkg:
                checksum_obj["package"] = pkg["checksum"]
            with open(crate_out_dir / ".cargo-checksum.json", "w") as f:
                json.dump(checksum_obj, f)
        else:
            raise Exception(f"Can't process source: {source}.")


def main() -> None:
    subcommand = sys.argv[1]
    if subcommand == "create-vendor-staging":
        create_vendor_staging(Path(sys.argv[2]), Path(sys.argv[3]))
    elif subcommand == "create-vendor":
        create_vendor(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise Exception(
            f"Unknown subcommand: {subcommand!r}. "
            "Expected 'create-vendor-staging' or 'create-vendor'."
        )


if __name__ == "__main__":
    main()
