"""Build and validate the immutable PID 1 runtime-closure manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


STORE_PATH = re.compile(
    r"^/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+$"
)
SONAME = re.compile(r"lib[A-Za-z0-9+_.-]+\.so(?:\.[0-9]+)*")
MAGIC = b"AOS_AUTHENTICATED_RUNTIME_CLOSURE"
VERSION = b"2"


def fail(message: str) -> "None":
    raise SystemExit(f"aos-selinux-runtime-manifest: {message}")


def graph_paths(attributes_file: Path, key: str) -> list[Path]:
    document = json.loads(attributes_file.read_text(encoding="utf-8"))
    entries = document.get(key)
    if not isinstance(entries, list) or not entries:
        fail(f"structured exportReferencesGraph key {key!r} is absent or empty")

    raw_paths: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            fail(f"structured closure entry {index} is not an object")
        path = entry.get("path")
        references = entry.get("references")
        nar_hash = entry.get("narHash")
        nar_size = entry.get("narSize")
        if not isinstance(path, str) or not STORE_PATH.fullmatch(path):
            fail(f"structured closure entry {index} has a noncanonical path")
        if not isinstance(references, list) or any(
            not isinstance(reference, str) or not STORE_PATH.fullmatch(reference)
            for reference in references
        ):
            fail(f"structured closure entry {index} has malformed references")
        if len(references) != len(set(references)):
            fail(f"structured closure entry {index} has duplicate references")
        if not isinstance(nar_hash, str) or not nar_hash:
            fail(f"structured closure entry {index} has no narHash")
        if not isinstance(nar_size, int) or isinstance(nar_size, bool) or nar_size < 0:
            fail(f"structured closure entry {index} has an invalid narSize")
        raw_paths.append(path)

    if len(raw_paths) != len(set(raw_paths)):
        fail("structured exportReferencesGraph contains duplicate paths")
    path_set = set(raw_paths)
    for index, entry in enumerate(entries):
        missing = set(entry["references"]) - path_set
        if missing:
            fail(f"structured closure entry {index} references absent paths")

    ordered = sorted(map(Path, raw_paths), key=lambda path: os.fsencode(path.name))
    if any(not STORE_PATH.fullmatch(str(path)) for path in ordered):
        fail("exportReferencesGraph contains a noncanonical store path")
    if any(not path.exists() for path in ordered):
        fail("exportReferencesGraph names an absent store path")
    return ordered


def run_patchelf(patchelf: Path, option: str, elf: Path) -> list[str] | None:
    result = subprocess.run(
        [patchelf, option, elf],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.splitlines()


def closure_owner(path: str, closure: set[str]) -> str | None:
    components = Path(path).parts
    if len(components) < 4 or components[:3] != ("/", "nix", "store"):
        return None
    owner = "/" + "/".join(components[1:4])
    return owner if owner in closure else None


def validate_symlinks(paths: list[Path]) -> None:
    closure = {str(path) for path in paths}

    for store_path in paths:
        candidates = [store_path] if store_path.is_symlink() else store_path.rglob("*")
        for candidate in candidates:
            if not candidate.is_symlink():
                continue
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                fail(f"runtime-closure symlink {candidate} cannot be resolved: {error}")
            if closure_owner(str(resolved), closure) is None:
                fail(f"runtime-closure symlink {candidate} escapes to {resolved}")


def validate_dlopen_inventory(
    paths: list[Path], patchelf: Path, known_sonames: list[str]
) -> dict[str, Path]:
    """Ensures every packaged shared-object identity remains inside pinned roots.

    PID 1's optional loaders select libraries by SONAME. The manifest pins the
    complete Nix reference closure, so indexing every available SONAME here,
    together with the no-cache/no-environment runtime contract, closes the
    alternate pathname by which a known dlopen target could be shadowed.
    """

    closure = {str(path) for path in paths}
    sonames: dict[str, Path] = {}
    for store_path in paths:
        candidates = [store_path] if store_path.is_file() else store_path.rglob("*")
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            soname_lines = run_patchelf(patchelf, "--print-soname", candidate)
            if soname_lines is None or not soname_lines or not soname_lines[0]:
                continue
            soname = soname_lines[0]
            if "/" in soname or "\0" in soname:
                fail(f"shared object {candidate} has a noncanonical SONAME")
            if closure_owner(str(candidate), closure) is None:
                fail(f"dlopen inventory entry escapes the runtime closure: {candidate}")
            previous = sonames.setdefault(soname, candidate)
            if previous != candidate:
                fail(f"ambiguous dlopen target {soname}: {previous} and {candidate}")

    for soname in known_sonames:
        if not SONAME.fullmatch(soname):
            fail(f"reviewed dlopen target has a noncanonical SONAME: {soname}")
        if soname not in sonames:
            fail(f"reviewed systemd dlopen target is absent: {soname}")

    return sonames


def canonical_search_directory(directory: str, elf: Path) -> Path:
    """Expands the supported origin token and returns a canonical directory."""

    raw_components = directory.split("/")
    if directory.startswith("/"):
        raw_components = raw_components[1:]
    if any(component in {"", ".", ".."} for component in raw_components):
        fail(f"{elf} has a noncanonical runtime search directory: {directory}")

    origin_tokens = ("$ORIGIN", "${ORIGIN}")
    expanded = directory
    for token in origin_tokens:
        if directory == token:
            expanded = str(elf.parent)
            break
        if directory.startswith(token + "/"):
            expanded = str(elf.parent / directory[len(token) + 1 :])
            break
    else:
        if "$" in directory:
            fail(f"{elf} has an unsupported loader token: {directory}")
        if not directory.startswith("/"):
            fail(f"{elf} has a relative runtime search directory: {directory}")

    if "$" in expanded:
        fail(f"{elf} has an unsupported loader token: {directory}")

    candidate = Path(expanded)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        fail(f"{elf} has an absent runtime search directory {directory}: {error}")
    if not resolved.is_dir() or candidate != resolved:
        fail(f"{elf} has a noncanonical runtime search directory: {directory}")
    return resolved


def validate_search_directories(
    directories: list[str], elf: Path, closure: set[str]
) -> list[Path]:
    resolved_directories: list[Path] = []
    for directory in directories:
        if not directory:
            fail(f"{elf} has an empty current-directory runtime search entry")
        resolved = canonical_search_directory(directory, elf)
        if closure_owner(str(resolved), closure) is None:
            fail(f"{elf} has an unpinned runtime search directory: {directory}")
        resolved_directories.append(resolved)
    return resolved_directories


def elf_string_candidates(elf: Path) -> tuple[set[str], set[str]]:
    """Returns bare SONAMEs and absolute DSO paths embedded in an ELF."""

    bare_sonames: set[str] = set()
    absolute_dsos: set[str] = set()
    for raw_value in elf.read_bytes().split(b"\0"):
        try:
            value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            continue

        if SONAME.fullmatch(value):
            bare_sonames.add(value)
        elif value.startswith("/") and SONAME.fullmatch(Path(value).name):
            absolute_dsos.add(value)

    return bare_sonames, absolute_dsos


def validate_absolute_dlopen_paths(paths: set[str], closure: set[str]) -> None:
    for path in paths:
        candidate = Path(path)
        if not path.startswith("/nix/store/") or path != str(candidate):
            fail(f"compiled PID 1 absolute dlopen path is not canonical store data: {path}")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            fail(f"compiled PID 1 absolute dlopen path is absent: {path}: {error}")
        if candidate != resolved or not resolved.is_file() or closure_owner(path, closure) is None:
            fail(f"compiled PID 1 absolute dlopen path escapes the runtime closure: {path}")


def dynamic_search_tags(readelf: Path, elf: Path) -> tuple[bool, bool]:
    """Returns whether an ELF carries DT_RPATH and DT_RUNPATH, respectively."""

    result = subprocess.run(
        [readelf, "-dW", elf],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail(f"cannot inspect dynamic search tags for {elf}: {result.stderr.strip()}")
    return "(RPATH)" in result.stdout, "(RUNPATH)" in result.stdout


def require_search_resolution(
    caller: Path,
    soname: str,
    search: list[Path],
    inventory: dict[str, Path],
) -> None:
    expected = inventory.get(soname)
    if expected is None:
        fail(f"optional-load caller {caller} requests an unpinned SONAME: {soname}")
    expected = expected.resolve(strict=True)

    for directory in search:
        candidate = directory / soname
        if candidate.is_file() and candidate.resolve(strict=True) == expected:
            return
    fail(f"optional-load caller {caller} cannot resolve {soname} from its pinned RPATH")


def resolve_needed_dso(
    caller: Path,
    soname: str,
    search: list[Path],
    closure: set[str],
    inventory: dict[str, Path],
) -> Path:
    """Resolves the first matching DT_NEEDED target to its closure-owned file."""

    expected = inventory.get(soname)
    if expected is None:
        fail(f"{caller} requests DT_NEEDED entry with no unique inventory target: {soname}")
    expected = expected.resolve(strict=True)

    for directory in search:
        candidate = directory / soname
        if not candidate.is_file():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            fail(f"{caller} cannot resolve DT_NEEDED entry {soname}: {error}")
        if not resolved.is_file() or closure_owner(str(resolved), closure) is None:
            fail(f"{caller} resolves DT_NEEDED entry {soname} outside the runtime closure")
        if resolved != expected:
            fail(f"{caller} resolves DT_NEEDED entry {soname} to the wrong inventory file")
        return resolved

    fail(f"{caller} cannot resolve DT_NEEDED entry {soname}")


def validate_compiled_dlopen_contract(
    paths: list[Path],
    systemd: Path,
    patchelf: Path,
    readelf: Path,
    literal_sonames: list[str],
    absent_literal_sonames: list[str],
    constructed_families: list[tuple[str, str]],
    constructed_sonames: list[str],
    inventory: dict[str, Path],
) -> None:
    """Audits the exact PID 1 ELF link set for alternate DSO load names."""

    closure = {str(path) for path in paths}
    pending: list[tuple[Path, tuple[Path, ...]]] = [(systemd, ())]
    visited_states: set[tuple[Path, tuple[Path, ...]]] = set()
    linked_elfs: set[Path] = set()
    compiled_literal_sonames: set[str] = set()
    absolute_dsos: set[str] = set()
    literal_callers: list[tuple[Path, set[str], list[Path]]] = []
    constructed_callers: list[tuple[Path, list[Path]]] = []

    if len(constructed_families) != len(set(constructed_families)):
        fail("reviewed constructed dlopen family list contains duplicates")
    family_inventory: dict[tuple[str, str], set[str]] = {}
    for prefix, suffix in constructed_families:
        if not prefix or not suffix or not SONAME.fullmatch(f"{prefix}x{suffix}"):
            fail(f"constructed dlopen family is noncanonical: {prefix!r}, {suffix!r}")
        family_members = {
            soname
            for soname in inventory
            if soname.startswith(prefix)
            and soname.endswith(suffix)
            and SONAME.fullmatch(soname)
        }
        if not family_members:
            fail(f"constructed dlopen family has no pinned member: {prefix}*{suffix}")
        family_inventory[(prefix, suffix)] = family_members

    while pending:
        elf, inherited_search = pending.pop()
        try:
            elf = elf.resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve compiled PID 1 link member {elf}: {error}")
        if not elf.is_file() or closure_owner(str(elf), closure) is None:
            fail(f"compiled PID 1 link member escapes the runtime closure: {elf}")
        state = (elf, inherited_search)
        if state in visited_states:
            continue
        visited_states.add(state)
        linked_elfs.add(elf)

        needed = run_patchelf(patchelf, "--print-needed", elf)
        rpath_lines = run_patchelf(patchelf, "--print-rpath", elf)
        soname_lines = run_patchelf(patchelf, "--print-soname", elf)
        if needed is None or rpath_lines is None or len(rpath_lines) > 1:
            fail(f"cannot audit the compiled PID 1 link set at {elf}")
        elf_sonames = {soname_lines[0]} if soname_lines and soname_lines[0] else set()

        bare, absolute = elf_string_candidates(elf)
        absolute_dsos.update(absolute)

        has_rpath, has_runpath = dynamic_search_tags(readelf, elf)
        if has_rpath and has_runpath:
            fail(f"compiled PID 1 link member {elf} has both DT_RPATH and DT_RUNPATH")
        encoded_search = rpath_lines[0] if rpath_lines else ""
        if not encoded_search and (has_rpath or has_runpath):
            fail(f"compiled PID 1 link member {elf} has an empty runtime search tag")
        own_search = validate_search_directories(
            encoded_search.split(":") if encoded_search else [], elf, closure
        )
        resolved_search = list(dict.fromkeys([*own_search, *inherited_search]))
        # DT_RPATH participates in descendant lookups; DT_RUNPATH is limited
        # to this object's direct dependencies.
        child_search = (
            tuple(resolved_search) if has_rpath else inherited_search
        )

        literal_candidates = {
            soname
            for soname in bare - set(needed) - elf_sonames
            if not any(
                soname.startswith(prefix) and soname.endswith(suffix)
                for prefix, suffix in constructed_families
            )
        }
        compiled_literal_sonames.update(literal_candidates)
        if literal_candidates:
            literal_callers.append((elf, literal_candidates, resolved_search))

        for soname in literal_candidates:
            if soname not in inventory:
                continue
            pending.append(
                (
                    resolve_needed_dso(
                        elf, soname, resolved_search, closure, inventory
                    ),
                    child_search,
                )
            )

        validate_absolute_dlopen_paths(absolute, closure)
        for path in absolute:
            pending.append((Path(path), child_search))

        elf_bytes = elf.read_bytes()
        for family, family_members in family_inventory.items():
            prefix, _ = family
            if prefix.encode("ascii") not in elf_bytes:
                continue
            constructed_callers.append((elf, resolved_search))
            for soname in family_members:
                pending.append(
                    (
                        resolve_needed_dso(
                            elf, soname, resolved_search, closure, inventory
                        ),
                        child_search,
                    )
                )

        for needed_soname in needed:
            pending.append(
                (
                    resolve_needed_dso(
                        elf,
                        needed_soname,
                        resolved_search,
                        closure,
                        inventory,
                    ),
                    child_search,
                )
            )

    reviewed_present_sonames = set(literal_sonames)
    reviewed_absent_sonames = set(absent_literal_sonames)
    if len(literal_sonames) != len(reviewed_present_sonames):
        fail("reviewed literal dlopen SONAME list contains duplicates")
    if len(absent_literal_sonames) != len(reviewed_absent_sonames):
        fail("reviewed absent dlopen SONAME list contains duplicates")
    if reviewed_present_sonames & reviewed_absent_sonames:
        fail("reviewed present and absent dlopen SONAME lists overlap")
    for soname in reviewed_absent_sonames:
        if not SONAME.fullmatch(soname):
            fail(f"reviewed absent dlopen target has a noncanonical SONAME: {soname}")
        if soname in inventory:
            fail(f"reviewed absent dlopen target is present: {soname}")

    reviewed_literal_sonames = reviewed_present_sonames | reviewed_absent_sonames
    if compiled_literal_sonames != reviewed_literal_sonames:
        missing = sorted(compiled_literal_sonames - reviewed_literal_sonames)
        stale = sorted(reviewed_literal_sonames - compiled_literal_sonames)
        fail(f"compiled PID 1 dlopen SONAME review drifted: missing={missing}, stale={stale}")

    for caller, sonames, search in literal_callers:
        for soname in sonames:
            if soname in reviewed_absent_sonames:
                continue
            require_search_resolution(caller, soname, search, inventory)

    validate_absolute_dlopen_paths(absolute_dsos, closure)

    linked_bytes = b"\0".join(elf.read_bytes() for elf in linked_elfs)
    for prefix, suffix in constructed_families:
        if prefix.encode("ascii") not in linked_bytes or suffix.encode("ascii") not in linked_bytes:
            fail(
                "constructed dlopen family is absent from the compiled PID 1 "
                f"link set: {prefix}*{suffix}"
            )

        family_members = family_inventory[(prefix, suffix)]
        family_callers = {}
        for caller, search in constructed_callers:
            if prefix.encode("ascii") in caller.read_bytes():
                family_callers[(caller, tuple(search))] = search
        if not family_callers:
            fail(f"constructed dlopen family has no compiled caller: {prefix}*{suffix}")
        for (caller, _), search in family_callers.items():
            for soname in family_members:
                require_search_resolution(caller, soname, search, inventory)

    if len(constructed_sonames) != len(set(constructed_sonames)):
        fail("reviewed constructed dlopen SONAME list contains duplicates")
    for soname in constructed_sonames:
        if soname not in inventory:
            fail(f"reviewed constructed dlopen target is absent: {soname}")
        if not any(
            soname.startswith(prefix) and soname.endswith(suffix)
            for prefix, suffix in constructed_families
        ):
            fail(f"reviewed constructed dlopen target has no family: {soname}")


def validate_elf_closure(paths: list[Path], systemd: Path, patchelf: Path) -> str:
    """Validates the interpreter and every closure-wide search directory.

    Direct dependency resolution belongs to the compiled PID 1 fixed-point
    walk. Unreachable executables and DSOs may have loader assumptions that
    are irrelevant to PID 1, but none may contribute an unowned RPATH if they
    enter its authenticated store-root closure.
    """

    closure = {str(path) for path in paths}
    interpreter_lines = run_patchelf(patchelf, "--print-interpreter", systemd)
    if interpreter_lines is None or len(interpreter_lines) != 1:
        fail("systemd does not have exactly one ELF interpreter")
    interpreter = interpreter_lines[0]
    if closure_owner(interpreter, closure) is None or not Path(interpreter).is_file():
        fail(f"systemd interpreter escapes the runtime closure: {interpreter}")
    try:
        physical_interpreter = Path(interpreter).resolve(strict=True)
    except OSError as error:
        fail(f"systemd interpreter cannot be resolved: {error}")
    if closure_owner(str(physical_interpreter), closure) is None or not physical_interpreter.is_file():
        fail(f"resolved systemd interpreter escapes the runtime closure: {physical_interpreter}")

    for store_path in paths:
        candidates = [store_path] if store_path.is_file() else store_path.rglob("*")
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                with candidate.open("rb") as source:
                    if source.read(4) != b"\x7fELF":
                        continue
            except OSError as error:
                fail(f"cannot inspect {candidate}: {error}")

            # Relocatable and static ELF objects have no dynamic search
            # contract. --print-needed is used only to classify the object;
            # dependency resolution remains in the reachable fixed-point walk.
            if run_patchelf(patchelf, "--print-needed", candidate) is None:
                continue
            rpath_lines = run_patchelf(patchelf, "--print-rpath", candidate)
            if rpath_lines is None or len(rpath_lines) > 1:
                fail(f"cannot determine the runtime search path for {candidate}")
            search = [] if not rpath_lines else rpath_lines[0].split(":")
            validate_search_directories(search, candidate, closure)

    return str(physical_interpreter)


def validate_static_executable(
    executable: Path,
    paths: list[Path],
    readelf: Path,
) -> None:
    """Requires one canonical closure-owned static ELF entry point."""

    closure = {str(path) for path in paths}
    if closure_owner(str(executable), closure) is None:
        fail(f"required static executable escapes the runtime closure: {executable}")
    try:
        resolved = executable.resolve(strict=True)
    except OSError as error:
        fail(f"required static executable cannot be resolved: {error}")
    if resolved != executable or not executable.is_file():
        fail(f"required static executable is absent or noncanonical: {executable}")

    header = subprocess.run(
        [readelf, "-hW", executable],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if header.returncode != 0 or "Type:" not in header.stdout:
        fail(f"required static executable is not an inspectable ELF: {executable}")

    program_headers = subprocess.run(
        [readelf, "-lW", executable],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if program_headers.returncode != 0 or "INTERP" in program_headers.stdout:
        fail(f"required executable has an ELF interpreter: {executable}")

    dynamic = subprocess.run(
        [readelf, "-dW", executable],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if dynamic.returncode != 0 or "(NEEDED)" in dynamic.stdout:
        fail(f"required executable has a dynamic dependency: {executable}")


def physical_lower_path(path: str | Path) -> str:
    """Maps a canonical logical store path beneath the physical lower store."""

    logical = str(path)
    candidate = Path(logical)
    components = logical.split("/")
    store_root = "/".join(components[:4])
    if (
        len(components) < 4
        or not STORE_PATH.fullmatch(store_root)
        or any(component in {"", ".", ".."} for component in components[4:])
        or logical != str(candidate)
    ):
        fail(f"cannot map noncanonical store path into the physical lower store: {logical}")
    return "/nix.lower/store/" + logical.removeprefix("/nix/store/")


def sha256_file(path: Path) -> str:
    """Hashes one immutable policy input without loading it all into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest_v2(data: bytes, expected_policy_digest: str) -> None:
    """Rejects malformed, downgraded, or mixed-version manifest encodings."""

    fields = data.split(b"\0")
    if not fields or fields[-1] != b"":
        fail("runtime-closure manifest is not NUL terminated")
    fields.pop()
    if len(fields) < 8 or fields[0] != MAGIC or fields[1] != VERSION:
        fail("runtime-closure manifest is not the exact v2 encoding")
    if fields[5] != expected_policy_digest.encode("ascii"):
        fail("runtime-closure manifest has the wrong immutable policy identity")
    try:
        count_text = fields[6].decode("ascii")
        count = int(count_text)
    except (UnicodeDecodeError, ValueError):
        fail("runtime-closure manifest has an invalid root count")
    if count <= 0 or count_text != str(count) or len(fields) != count + 8:
        fail("runtime-closure manifest has a noncanonical root count")

    roots = fields[7 : 7 + count]
    if roots != sorted(set(roots)) or any(not root for root in roots):
        fail("runtime-closure manifest roots are empty, duplicate, or unordered")
    digest = fields[-1]
    if len(digest) != 64:
        fail("runtime-closure manifest has an invalid digest field")
    payload = b"\0".join(fields[:-1]) + b"\0"
    if digest != hashlib.sha256(payload).hexdigest().encode("ascii"):
        fail("runtime-closure manifest digest does not authenticate its fields")


def write_manifest(
    output: Path,
    systemd: Path,
    interpreter: str,
    static_executable: Path,
    policy_digest: str,
    paths: list[Path],
) -> str:
    fields = [
        MAGIC,
        VERSION,
        os.fsencode(physical_lower_path(systemd)),
        os.fsencode(physical_lower_path(interpreter)),
        os.fsencode(physical_lower_path(static_executable)),
        policy_digest.encode("ascii"),
        str(len(paths)).encode("ascii"),
        *(os.fsencode(path.name) for path in paths),
    ]
    payload = b"\0".join(fields) + b"\0"
    digest = hashlib.sha256(payload).hexdigest()
    encoded = payload + digest.encode("ascii") + b"\0"
    validate_manifest_v2(encoded, policy_digest)
    output.write_bytes(encoded)
    return digest


def write_header(
    output: Path,
    systemd: Path,
    interpreter: str,
    static_executable: Path,
    policy_digest: str,
    count: int,
    digest: str,
) -> None:
    output.write_text(
        "\n".join(
            [
                "#pragma once",
                f'#define AOS_PHYSICAL_SYSTEMD_PATH "{physical_lower_path(systemd)}"',
                f'#define AOS_PHYSICAL_INTERPRETER_PATH "{physical_lower_path(interpreter)}"',
                f'#define AOS_RUNTIME_ROOTS_PATH "{static_executable}"',
                f'#define AOS_PHYSICAL_RUNTIME_ROOTS_PATH "{physical_lower_path(static_executable)}"',
                f'#define AOS_EXPECTED_POLICY_SHA256 "{policy_digest}"',
                f"#define AOS_RUNTIME_CLOSURE_COUNT {count}U",
                f'#define AOS_RUNTIME_CLOSURE_DIGEST "{digest}"',
                "",
            ]
        ),
        encoding="ascii",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attrs", type=Path, required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--systemd", type=Path, required=True)
    parser.add_argument("--required-static-executable", type=Path, required=True)
    parser.add_argument("--expected-policy", type=Path, required=True)
    parser.add_argument("--patchelf", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--header", type=Path, required=True)
    parser.add_argument("--known-dlopen-soname", action="append", default=[])
    parser.add_argument("--known-absent-dlopen-soname", action="append", default=[])
    parser.add_argument(
        "--constructed-dlopen-family", action="append", nargs=2, default=[]
    )
    parser.add_argument("--known-constructed-dlopen-soname", action="append", default=[])
    arguments = parser.parse_args()

    paths = graph_paths(arguments.attrs, arguments.key)
    if arguments.systemd.parents[2] not in paths:
        fail("systemd output is absent from its exported runtime closure")
    if not arguments.systemd.is_file():
        fail("systemd executable is absent")
    if arguments.required_static_executable.parents[1] not in paths:
        fail("required static executable output is absent from the exported runtime closure")

    validate_symlinks(paths)
    interpreter = validate_elf_closure(paths, arguments.systemd, arguments.patchelf)
    validate_static_executable(
        arguments.required_static_executable,
        paths,
        arguments.readelf,
    )
    reviewed_sonames = (
        arguments.known_dlopen_soname + arguments.known_constructed_dlopen_soname
    )
    inventory = validate_dlopen_inventory(paths, arguments.patchelf, reviewed_sonames)
    validate_compiled_dlopen_contract(
        paths,
        arguments.systemd,
        arguments.patchelf,
        arguments.readelf,
        arguments.known_dlopen_soname,
        arguments.known_absent_dlopen_soname,
        arguments.constructed_dlopen_family,
        arguments.known_constructed_dlopen_soname,
        inventory,
    )
    policy_digest = sha256_file(arguments.expected_policy)
    digest = write_manifest(
        arguments.output,
        arguments.systemd,
        interpreter,
        arguments.required_static_executable,
        policy_digest,
        paths,
    )
    write_header(
        arguments.header,
        arguments.systemd,
        interpreter,
        arguments.required_static_executable,
        policy_digest,
        len(paths),
        digest,
    )


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        fail(str(error))
