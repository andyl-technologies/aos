"""Build deterministic SELinux label plans for AOS filesystem images.

The image builders cannot rely on labels attached to their staging trees: a
Nix sandbox does not have the authority to create ``security.selinux`` xattrs.
This module instead derives labels from the production file-context database
and emits exact, type-qualified entries for the image namespace.

Paths below ``/nix/store`` and ``/nix.lower/store`` need additional handling.
Reference Policy does not know content-addressed AOS store paths, while the
kernel ultimately checks the target inode rather than a conventional symlink.
The planner therefore propagates labels from conventional aliases and uses
ELF structure for the remaining store files. Ambiguous executable ET_DYN files
are rejected instead of being granted a generic executable or library label.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import stat
import struct
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from verify_context_dump import VerificationError, parse_dump_records


DEFAULT_CONTEXT_TYPES = frozenset({"default_t", "unlabeled_t"})
GENERIC_CONTEXT_TYPES = frozenset({"bin_t", "lib_t", "usr_t"})
EXPLICIT_NO_LABEL_PATHS = frozenset({"/proc", "/sys", "/sys/fs/selinux"})

ET_EXEC = 2
ET_DYN = 3
PT_DYNAMIC = 2
PT_INTERP = 3
DT_NULL = 0
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_PIE = 0x08000000


class PlanError(ValueError):
    """Reports an input that cannot be assigned one unambiguous label."""


class InodeKind(Enum):
    """Names the inode kinds understood by SELinux file-context lookups."""

    block = "b"
    character = "c"
    directory = "d"
    fifo = "p"
    regular = "f"
    socket = "s"
    symlink = "l"

    @property
    def file_context_qualifier(self) -> str:
        """Returns the qualifier syntax used by a file-contexts source."""

        return "--" if self is InodeKind.regular else f"-{self.value}"

    @classmethod
    def from_mode(cls, mode: int) -> "InodeKind":
        """Returns the kind represented by an ``st_mode`` value.

        Raises:
            PlanError: If ``mode`` names an unsupported inode kind.
        """

        file_type = stat.S_IFMT(mode)
        kinds = {
            stat.S_IFBLK: cls.block,
            stat.S_IFCHR: cls.character,
            stat.S_IFDIR: cls.directory,
            stat.S_IFIFO: cls.fifo,
            stat.S_IFREG: cls.regular,
            stat.S_IFSOCK: cls.socket,
            stat.S_IFLNK: cls.symlink,
        }
        try:
            return kinds[file_type]
        except KeyError as error:
            raise PlanError(f"unsupported inode mode 0o{mode:o}") from error


@dataclass(frozen=True)
class ElfIdentity:
    """Records the executable/library signals carried by an ELF file."""

    object_type: int
    has_interpreter: bool
    has_pie_flag: bool

    @property
    def is_pie(self) -> bool:
        """Reports whether ELF metadata positively identifies a PIE."""

        return self.object_type == ET_DYN and (
            self.has_interpreter or self.has_pie_flag
        )


@dataclass(frozen=True)
class InventoryEntry:
    """Describes one inode in an image staging tree."""

    path: str
    source: Path | None
    mode: int
    kind: InodeKind
    inode_key: tuple[int, int] | None
    symlink_target: str | None


@dataclass(frozen=True)
class PlannedLabel:
    """Associates one image path and actual inode kind with a label."""

    path: str
    kind: InodeKind
    context: str | None


def context_type(context: str) -> str:
    """Extracts the type field from a raw SELinux context.

    Raises:
        PlanError: If ``context`` is not a valid non-MLS or MLS raw context.
    """

    if any(character.isspace() for character in context) or "\x00" in context:
        raise PlanError(f"invalid SELinux context {context!r}")

    fields = context.split(":", 3)
    if len(fields) not in {3, 4} or not all(fields):
        raise PlanError(f"invalid SELinux context {context!r}")
    return fields[2]


def _context_with_type(contexts: Iterable[str], desired_type: str, path: str) -> str:
    """Substitutes a type without inventing a policy's MLS shape or identity."""

    templates: set[tuple[str, str, str | None]] = set()
    for context in contexts:
        fields = context.split(":", 3)
        context_type(context)
        templates.add((fields[0], fields[1], fields[3] if len(fields) == 4 else None))

    if not templates:
        raise PlanError(f"no authoritative context template for {path}")
    if len(templates) != 1:
        ordered_templates = sorted(templates, key=repr)
        raise PlanError(
            f"conflicting context templates for {path}: {ordered_templates}"
        )

    user, role, range_field = templates.pop()
    fields = [user, role, desired_type]
    if range_field is not None:
        fields.append(range_field)
    return ":".join(fields)


def _unpack_from(fmt: str, data: bytes, offset: int, description: str) -> tuple:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PlanError(f"truncated ELF {description}")
    return struct.unpack_from(fmt, data, offset)


def _read_at(file, file_size: int, offset: int, size: int, description: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > file_size:
        raise PlanError(f"ELF {description} exceeds file")
    file.seek(offset)
    data = file.read(size)
    if len(data) != size:
        raise PlanError(f"truncated ELF {description}")
    return data


def inspect_elf(path: Path) -> ElfIdentity | None:
    """Reads the bounded ELF metadata needed for secure label selection.

    Static PIE is deliberately recognized through ``DF_1_PIE``. It may omit
    ``PT_INTERP`` because ``-static-pie`` executables run without a dynamic
    linker. An ELF-looking but malformed file is rejected rather than treated
    as an ordinary executable.

    Raises:
        OSError: If the file cannot be read.
        PlanError: If ELF headers or referenced tables are malformed.
    """

    with path.open("rb") as file:
        file_size = os.fstat(file.fileno()).st_size
        identification = file.read(16)
        if not identification.startswith(b"\x7fELF"):
            return None
        if len(identification) < 16:
            raise PlanError(f"truncated ELF identification in {path}")

        elf_class = identification[4]
        byte_order = identification[5]
    if byte_order == 1:
        endian = "<"
    elif byte_order == 2:
        endian = ">"
    else:
        raise PlanError(f"invalid ELF byte order in {path}")

    header_size = 52 if elf_class == 1 else 64 if elf_class == 2 else 0
    if not header_size:
        raise PlanError(f"invalid ELF class in {path}")
    with path.open("rb") as file:
        file_size = os.fstat(file.fileno()).st_size
        header = _read_at(file, file_size, 0, header_size, "header")

        if elf_class == 1:
            object_type = _unpack_from(f"{endian}H", header, 16, "type")[0]
            program_offset = _unpack_from(f"{endian}I", header, 28, "phoff")[0]
            entry_size = _unpack_from(f"{endian}H", header, 42, "phentsize")[0]
            entry_count = _unpack_from(f"{endian}H", header, 44, "phnum")[0]
            minimum_entry_size = 32
            dynamic_entry_format = f"{endian}II"

            def program_fields(data: bytes) -> tuple[int, int, int]:
                program_type, file_offset = _unpack_from(
                    f"{endian}II", data, 0, "program header"
                )
                file_size = _unpack_from(
                    f"{endian}I", data, 16, "program file size"
                )[0]
                return program_type, file_offset, file_size

        else:
            object_type = _unpack_from(f"{endian}H", header, 16, "type")[0]
            program_offset = _unpack_from(f"{endian}Q", header, 32, "phoff")[0]
            entry_size = _unpack_from(f"{endian}H", header, 54, "phentsize")[0]
            entry_count = _unpack_from(f"{endian}H", header, 56, "phnum")[0]
            minimum_entry_size = 56
            dynamic_entry_format = f"{endian}QQ"

            def program_fields(data: bytes) -> tuple[int, int, int]:
                program_type = _unpack_from(
                    f"{endian}I", data, 0, "program type"
                )[0]
                file_offset = _unpack_from(
                    f"{endian}Q", data, 8, "program offset"
                )[0]
                segment_size = _unpack_from(
                    f"{endian}Q", data, 32, "program file size"
                )[0]
                return program_type, file_offset, segment_size

        if entry_count == 0xFFFF:
            raise PlanError(
                f"extended ELF program-header counts are unsupported: {path}"
            )
        if entry_count > 4096:
            raise PlanError(f"excessive ELF program-header count in {path}")
        if entry_count and entry_size < minimum_entry_size:
            raise PlanError(f"undersized ELF program header in {path}")
        if entry_size > 4096:
            raise PlanError(f"oversized ELF program header in {path}")
        if program_offset + entry_size * entry_count > file_size:
            raise PlanError(f"ELF program-header table exceeds {path}")

        has_interpreter = False
        dynamic_ranges: list[tuple[int, int]] = []
        for index in range(entry_count):
            offset = program_offset + index * entry_size
            program_header = _read_at(
                file, file_size, offset, entry_size, "program header"
            )
            program_type, file_offset, segment_size = program_fields(program_header)
            if file_offset + segment_size > file_size:
                raise PlanError(f"ELF program segment exceeds {path}")
            if program_type == PT_INTERP:
                has_interpreter = True
            elif program_type == PT_DYNAMIC:
                dynamic_ranges.append((file_offset, segment_size))

        dynamic_entry_size = struct.calcsize(dynamic_entry_format)
        has_pie_flag = False
        for file_offset, segment_size in dynamic_ranges:
            if segment_size > 4 * 1024 * 1024:
                raise PlanError(f"oversized ELF dynamic table in {path}")
            if segment_size % dynamic_entry_size != 0:
                raise PlanError(f"misaligned ELF dynamic table in {path}")
            dynamic = _read_at(
                file, file_size, file_offset, segment_size, "dynamic table"
            )
            for offset in range(0, segment_size, dynamic_entry_size):
                tag, value = _unpack_from(
                    dynamic_entry_format, dynamic, offset, "dynamic entry"
                )
                if tag == DT_NULL:
                    break
                if tag == DT_FLAGS_1 and value & DF_1_PIE:
                    has_pie_flag = True

        return ElfIdentity(object_type, has_interpreter, has_pie_flag)


def _store_relative_path(path: str) -> str | None:
    for prefix in ("/nix/store/", "/nix.lower/store/"):
        if path.startswith(prefix):
            components = path[len(prefix) :].split("/", 1)
            return components[1] if len(components) == 2 else ""
    return None


def _is_nix_namespace_path(path: str) -> bool:
    return path in {"/nix", "/nix/store", "/nix.lower", "/nix.lower/store"} or (
        _store_relative_path(path) is not None
    )


def _has_library_path_authority(path: str) -> bool:
    relative = _store_relative_path(path)
    if relative is None:
        return False
    first_component = relative.split("/", 1)[0]
    return first_component in {"lib", "lib32", "lib64"}


def classify_store_regular(path: str, source: Path, mode: int) -> str:
    """Returns the fallback type for an unmatched Nix-store regular file.

    Raises:
        OSError: If file metadata cannot be read.
        PlanError: If executable ELF metadata is ambiguous or inconsistent.
    """

    identity = inspect_elf(source)
    executable = bool(mode & 0o111)
    if identity is not None:
        if identity.object_type == ET_EXEC:
            if not executable:
                raise PlanError(f"ET_EXEC file is not executable: {path}")
            return "bin_t"
        if identity.object_type != ET_DYN:
            return "usr_t"
        if identity.is_pie:
            if not executable:
                raise PlanError(f"PIE file is not executable: {path}")
            return "bin_t"
        if not executable or _has_library_path_authority(path):
            return "lib_t"
        raise PlanError(f"ambiguous executable ET_DYN requires explicit authority: {path}")

    if executable:
        return "bin_t"
    return "usr_t"


def inventory_tree(root: Path) -> list[InventoryEntry]:
    """Returns a bytewise-ordered, no-follow inventory beneath ``root``.

    Raises:
        OSError: If the tree cannot be read.
        PlanError: If a path cannot be represented unambiguously.
    """

    entries: list[InventoryEntry] = []
    for source in [root, *sorted(root.rglob("*"), key=lambda item: os.fsencode(item))]:
        relative = source.relative_to(root)
        path = "/" if not relative.parts else "/" + relative.as_posix()
        if "\n" in path or "\r" in path or "\x00" in path:
            raise PlanError(f"unsupported control character in image path {path!r}")

        metadata = source.lstat()
        kind = InodeKind.from_mode(metadata.st_mode)
        inode_key = None
        if kind is not InodeKind.symlink:
            inode_key = (metadata.st_dev, metadata.st_ino)
        symlink_target = os.readlink(source) if kind is InodeKind.symlink else None
        entries.append(
            InventoryEntry(
                path=path,
                source=source,
                mode=metadata.st_mode,
                kind=kind,
                inode_key=inode_key,
                symlink_target=symlink_target,
            )
        )
    return entries


def inventory_composefs_dump(path: Path) -> list[InventoryEntry]:
    """Returns the exact inode inventory described by a composefs dump.

    Composefs metadata images contain only directories, regular files, and
    symlinks. Each record must describe its own inode: hard-link identity
    cannot be reconstructed safely from the text format, so link counts other
    than one are rejected.

    Raises:
        OSError: If the dump cannot be read.
        PlanError: If a record is unsafe or cannot be represented exactly.
    """

    kind_by_name = {
        "directory": InodeKind.directory,
        "regular": InodeKind.regular,
        "symlink": InodeKind.symlink,
    }
    try:
        records = parse_dump_records(path)
    except VerificationError as error:
        raise PlanError(f"invalid composefs dump: {error}") from error

    entries: list[InventoryEntry] = []
    for index, record in enumerate(records):
        try:
            kind = kind_by_name[record.kind]
        except KeyError as error:
            raise PlanError(
                f"unsupported composefs inode kind {record.kind}: {record.path}"
            ) from error
        if record.link_count != 1:
            raise PlanError(
                f"composefs hard-link identity is ambiguous: {record.path}"
            )
        symlink_target = None
        if kind is InodeKind.symlink:
            try:
                symlink_target = record.payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise PlanError(
                    f"non-UTF-8 symlink target for {record.path}"
                ) from error
            if any(character in symlink_target for character in "\x00\r\n"):
                raise PlanError(
                    f"control character in symlink target for {record.path}"
                )

        entries.append(
            InventoryEntry(
                path=record.path,
                source=None,
                mode=kind_mode(kind),
                kind=kind,
                inode_key=(0, index),
                symlink_target=symlink_target,
            )
        )
    return entries


def normalize_lookup_prefix(prefix: str) -> str:
    """Returns one canonical absolute runtime lookup prefix.

    Raises:
        PlanError: If the prefix is relative, noncanonical, or contains a
            control character.
    """

    if any(character in prefix for character in "\x00\r\n"):
        raise PlanError("lookup prefix contains a control character")
    if not prefix.startswith("/"):
        raise PlanError(f"lookup prefix is not absolute: {prefix!r}")
    if prefix == "/":
        return prefix
    if prefix != "/" and prefix.endswith("/"):
        raise PlanError(f"lookup prefix has a trailing slash: {prefix!r}")
    components = prefix.split("/")[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise PlanError(f"lookup prefix is not canonical: {prefix!r}")
    return prefix


def runtime_lookup_path(image_path: str, lookup_prefix: str) -> str:
    """Maps an image-internal path to its absolute runtime mount path."""

    prefix = normalize_lookup_prefix(lookup_prefix)
    if image_path == "/":
        return prefix
    if prefix == "/":
        return image_path
    return prefix + image_path


def _image_path_from_runtime(path: str, lookup_prefix: str) -> str | None:
    """Maps an absolute runtime path back into an image namespace."""

    prefix = normalize_lookup_prefix(lookup_prefix)
    if prefix == "/":
        return path
    if path == prefix:
        return "/"
    if path.startswith(prefix + "/"):
        return path[len(prefix) :]
    return None


class _SelinuxOption(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("value", ctypes.c_void_p)]


class FileContextResolver:
    """Resolves raw contexts through one persistent libselinux handle."""

    def __init__(self, library: Path, file_contexts: Path):
        self._library = ctypes.CDLL(os.fspath(library), use_errno=True)
        self._library.selabel_open.argtypes = [
            ctypes.c_uint,
            ctypes.POINTER(_SelinuxOption),
            ctypes.c_uint,
        ]
        self._library.selabel_open.restype = ctypes.c_void_p
        self._library.selabel_lookup_raw.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        self._library.selabel_lookup_raw.restype = ctypes.c_int
        self._library.selabel_close.argtypes = [ctypes.c_void_p]
        self._library.selabel_close.restype = None
        self._library.freecon.argtypes = [ctypes.c_void_p]
        self._library.freecon.restype = None

        encoded_path = os.fsencode(file_contexts)
        self._path_buffer = ctypes.create_string_buffer(encoded_path)
        options = (_SelinuxOption * 2)(
            _SelinuxOption(3, ctypes.addressof(self._path_buffer)),
            # BASEONLY prevents an adjacent .local file from changing authority.
            _SelinuxOption(2, 1),
        )
        self._handle = self._library.selabel_open(0, options, len(options))
        if not self._handle:
            error_number = ctypes.get_errno()
            raise PlanError(
                f"cannot open file contexts {file_contexts}: "
                f"{os.strerror(error_number)}"
            )

    def close(self) -> None:
        """Closes the persistent label handle."""

        if self._handle:
            self._library.selabel_close(self._handle)
            self._handle = None

    def __enter__(self) -> "FileContextResolver":
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()

    def lookup(self, path: str, kind: InodeKind) -> str | None:
        """Returns the raw context for ``path`` and its actual inode kind.

        ``<<none>>`` entries and genuinely absent specifications both surface
        as ``ENOENT`` from libselinux and return ``None``. The complete-plan
        pass decides whether that result is an explicitly allowed pseudo-fs
        mountpoint or a fatal omission.

        Raises:
            PlanError: If libselinux reports an error other than ``ENOENT``.
        """

        if not self._handle:
            raise PlanError("file-context resolver is closed")

        context_pointer = ctypes.c_void_p()
        result = self._library.selabel_lookup_raw(
            self._handle,
            ctypes.byref(context_pointer),
            os.fsencode(path),
            kind_mode(kind),
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == 2:
                return None
            raise PlanError(
                f"file-context lookup failed for {path}: "
                f"{os.strerror(error_number)}"
            )
        if not context_pointer.value:
            raise PlanError(f"file-context lookup returned an empty pointer for {path}")

        try:
            encoded = ctypes.string_at(context_pointer.value)
            context = encoded.decode("ascii")
        except UnicodeDecodeError as error:
            raise PlanError(f"non-ASCII SELinux context for {path}") from error
        finally:
            self._library.freecon(context_pointer)
        context_type(context)
        return context


def kind_mode(kind: InodeKind) -> int:
    """Returns the POSIX type bits consumed by ``selabel_lookup_raw``."""

    modes = {
        InodeKind.block: stat.S_IFBLK,
        InodeKind.character: stat.S_IFCHR,
        InodeKind.directory: stat.S_IFDIR,
        InodeKind.fifo: stat.S_IFIFO,
        InodeKind.regular: stat.S_IFREG,
        InodeKind.socket: stat.S_IFSOCK,
        InodeKind.symlink: stat.S_IFLNK,
    }
    try:
        return modes[kind]
    except KeyError as error:
        raise PlanError(f"unsupported inode kind {kind}") from error


def _resolve_symlink_target(
    entry: InventoryEntry,
    entries_by_path: Mapping[str, InventoryEntry],
    lookup_prefix: str = "/",
) -> InventoryEntry | None:
    def absolute_components(path: str) -> list[str]:
        if not path.startswith("/"):
            raise PlanError(f"symlink escaped image namespace: {entry.path}")
        components = path.split("/")[1:]
        if lookup_prefix == "/" and (
            components[:2] == ["nix", "store"]
            and "/nix.lower/store" in entries_by_path
        ):
            components[:2] = ["nix.lower", "store"]
        return components

    pending = absolute_components(entry.path)
    resolved: list[str] = []
    expansion_count = 0
    while pending:
        component = pending.pop(0)
        if component in {"", "."}:
            continue
        if component == "..":
            if resolved:
                resolved.pop()
            continue

        candidate_components = [*resolved, component]
        candidate_path = "/" + "/".join(candidate_components)
        current = entries_by_path.get(candidate_path)
        if current is None:
            return None
        if current.kind is not InodeKind.symlink:
            resolved.append(component)
            continue
        if current.symlink_target is None:
            raise PlanError(f"symlink has no target while resolving {entry.path}")

        expansion_count += 1
        if expansion_count > 40:
            raise PlanError(f"too many symlinks while resolving {entry.path}")

        if current.symlink_target.startswith("/"):
            target_path = _image_path_from_runtime(
                current.symlink_target, lookup_prefix
            )
            if target_path is None:
                return None
            resolved = []
            target_components = absolute_components(target_path)
        else:
            target_components = current.symlink_target.split("/")
        pending = [*target_components, *pending]

    path = "/" if not resolved else "/" + "/".join(resolved)
    return entries_by_path.get(path)


def _choose_alias_context(path: str, contexts: Iterable[str]) -> str | None:
    unique = sorted(set(contexts))
    specific = [
        context
        for context in unique
        if context_type(context) not in GENERIC_CONTEXT_TYPES
        and context_type(context) not in DEFAULT_CONTEXT_TYPES
    ]
    if len(specific) > 1:
        raise PlanError(f"conflicting specific alias labels for {path}: {specific}")
    if specific:
        return specific[0]

    non_default = [
        context for context in unique if context_type(context) not in DEFAULT_CONTEXT_TYPES
    ]
    if len(non_default) > 1:
        raise PlanError(f"conflicting generic alias labels for {path}: {non_default}")
    return non_default[0] if non_default else None


def _alias_targets(
    entries: Sequence[InventoryEntry],
    entries_by_path: Mapping[str, InventoryEntry],
    lookup_prefix: str,
) -> Iterable[tuple[str, InventoryEntry]]:
    """Yields concrete targets for file and directory symlink aliases."""

    emitted: set[tuple[str, str]] = set()
    for alias in entries:
        if alias.kind is not InodeKind.symlink:
            continue
        target = _resolve_symlink_target(alias, entries_by_path, lookup_prefix)
        if target is None:
            continue

        candidates = [target]
        if target.kind is InodeKind.directory:
            prefix = target.path.rstrip("/") + "/"
            candidates.extend(
                candidate for candidate in entries if candidate.path.startswith(prefix)
            )

        for candidate in candidates:
            resolved = _resolve_symlink_target(
                candidate, entries_by_path, lookup_prefix
            )
            if resolved is None:
                continue
            suffix = candidate.path[len(target.path) :]
            alias_path = alias.path.rstrip("/") + suffix
            binding = (alias_path, resolved.path)
            if binding in emitted:
                continue
            emitted.add(binding)
            yield alias_path, resolved


def plan_labels(
    entries: Sequence[InventoryEntry],
    resolver: FileContextResolver,
    dynamic_loaders: Iterable[str] = (),
    lookup_prefix: str = "/",
) -> list[PlannedLabel]:
    """Returns one deterministic, complete label decision per image path.

    Raises:
        OSError: If source files or the lookup executable cannot be read.
        PlanError: If any label is missing, unsafe, or ambiguous.
    """

    lookup_prefix = normalize_lookup_prefix(lookup_prefix)
    entries_by_path = {entry.path: entry for entry in entries}
    if len(entries_by_path) != len(entries):
        raise PlanError("inventory contains duplicate image paths")
    loader_paths = frozenset(dynamic_loaders)
    direct_contexts = {
        entry.path: resolver.lookup(
            runtime_lookup_path(entry.path, lookup_prefix), entry.kind
        )
        for entry in entries
    }
    alias_contexts: dict[tuple[int, int], list[str]] = {}

    for alias_path, target in _alias_targets(
        entries, entries_by_path, lookup_prefix
    ):
        if target.inode_key is None:
            continue
        target_runtime_path = runtime_lookup_path(target.path, lookup_prefix)
        if _store_relative_path(target_runtime_path) is None:
            continue

        context = resolver.lookup(
            runtime_lookup_path(alias_path, lookup_prefix), target.kind
        )
        if context is not None:
            alias_contexts.setdefault(target.inode_key, []).append(context)

    inode_members: dict[tuple[int, int], list[InventoryEntry]] = {}
    for entry in entries:
        if entry.inode_key is not None:
            inode_members.setdefault(entry.inode_key, []).append(entry)

    inode_contexts: dict[tuple[int, int], str | None] = {}
    for inode_key, members in inode_members.items():
        in_store = any(
            _is_nix_namespace_path(
                runtime_lookup_path(member.path, lookup_prefix)
            )
            for member in members
        )
        if in_store and members[0].kind not in {
            InodeKind.directory,
            InodeKind.regular,
        }:
            raise PlanError(
                f"special inode is forbidden in immutable store: {members[0].path}"
            )
        candidates = [
            context
            for member in members
            if (context := direct_contexts[member.path]) is not None
        ]
        candidates.extend(alias_contexts.get(inode_key, []))
        selected = _choose_alias_context(members[0].path, candidates)

        loader_member = next(
            (
                member
                for member in members
                if runtime_lookup_path(member.path, lookup_prefix) in loader_paths
            ),
            None,
        )
        if loader_member is not None:
            conflicting = [
                context
                for context in candidates
                if context_type(context) not in GENERIC_CONTEXT_TYPES
                and context_type(context) not in DEFAULT_CONTEXT_TYPES
                and context_type(context) != "ld_so_t"
            ]
            if conflicting:
                raise PlanError(
                    f"dynamic-loader authority conflicts for {loader_member.path}: "
                    f"{sorted(set(conflicting))}"
                )
            selected = _context_with_type(candidates, "ld_so_t", loader_member.path)
        elif in_store and selected is None:
            representative = members[0]
            if representative.kind is InodeKind.directory:
                fallback_type = "usr_t"
            elif representative.kind is InodeKind.regular:
                if representative.source is None:
                    raise PlanError(
                        "store regular inode has no authoritative source: "
                        f"{representative.path}"
                    )
                fallback_type = classify_store_regular(
                    runtime_lookup_path(representative.path, lookup_prefix),
                    representative.source,
                    representative.mode,
                )
            else:
                raise PlanError(
                    "special inode is forbidden in immutable store: "
                    f"{representative.path}"
                )
            selected = _context_with_type(candidates, fallback_type, representative.path)

        if selected is None:
            runtime_paths = {
                runtime_lookup_path(member.path, lookup_prefix)
                for member in members
            }
            if not runtime_paths.issubset(EXPLICIT_NO_LABEL_PATHS):
                raise PlanError(f"no SELinux label for {members[0].path}")
        elif context_type(selected) in DEFAULT_CONTEXT_TYPES:
            raise PlanError(
                f"unsafe default SELinux label for {members[0].path}: {selected}"
            )
        inode_contexts[inode_key] = selected

    planned: list[PlannedLabel] = []
    for entry in entries:
        if entry.inode_key is not None:
            selected = inode_contexts[entry.inode_key]
        else:
            selected = direct_contexts[entry.path]
            entry_runtime_path = runtime_lookup_path(entry.path, lookup_prefix)
            if _is_nix_namespace_path(entry_runtime_path):
                if entry.kind is not InodeKind.symlink:
                    raise PlanError(f"untracked store inode: {entry.path}")
                if selected is None or context_type(selected) in DEFAULT_CONTEXT_TYPES:
                    selected = _context_with_type(
                        [selected] if selected is not None else [],
                        "usr_t",
                        entry.path,
                    )
            if (
                selected is None
                and entry_runtime_path not in EXPLICIT_NO_LABEL_PATHS
            ):
                raise PlanError(f"no SELinux label for {entry.path}")
            if selected is not None and context_type(selected) in DEFAULT_CONTEXT_TYPES:
                raise PlanError(f"unsafe default SELinux label for {entry.path}: {selected}")
        planned.append(PlannedLabel(entry.path, entry.kind, selected))

    return planned


def _escape_file_context_path(path: str) -> str:
    safe = b"/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    return "".join(
        chr(byte) if byte in safe else f"\\x{byte:02x}"
        for byte in path.encode("utf-8")
    )


def write_outputs(
    base_file_contexts: Path,
    labels: Sequence[PlannedLabel],
    output_file_contexts: Path,
    output_map: Path,
    lookup_prefix: str = "/",
) -> None:
    """Writes the merged exact file-context database and canonical JSON map."""

    base = base_file_contexts.read_text(encoding="utf-8")
    with output_file_contexts.open("w", encoding="utf-8", newline="\n") as output:
        output.write(base)
        if base and not base.endswith("\n"):
            output.write("\n")
        output.write("\n# Exact AOS image-inode labels. Generated; do not edit.\n")
        ordered_labels = sorted(
            labels, key=lambda label: (os.fsencode(label.path), label.kind.value)
        )
        for label in ordered_labels:
            if label.context is None:
                continue
            lookup_path = runtime_lookup_path(label.path, lookup_prefix)
            output.write(
                f"{_escape_file_context_path(lookup_path)}"
                f"\t{label.kind.file_context_qualifier}\t{label.context}\n"
            )

    encoded = {
        "version": 1,
        "entries": [
            {
                "path": label.path,
                "kind": label.kind.name,
                "context": label.context,
            }
            for label in ordered_labels
        ],
    }
    output_map.write_text(
        json.dumps(encoded, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parses the standalone planner command line."""

    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--root", type=Path)
    inputs.add_argument("--composefs-dump", type=Path)
    parser.add_argument("--file-contexts", type=Path, required=True)
    parser.add_argument("--libselinux", type=Path, required=True)
    parser.add_argument("--output-file-contexts", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    parser.add_argument("--dynamic-loader", action="append", default=[])
    parser.add_argument("--lookup-prefix", default="/")
    options = parser.parse_args(argv)
    if options.composefs_dump is not None and options.dynamic_loader:
        parser.error("--dynamic-loader cannot be used with --composefs-dump")
    return options


def main(argv: Sequence[str] | None = None) -> int:
    """Builds a complete label plan from a staged image tree."""

    options = parse_args(sys.argv[1:] if argv is None else argv)
    lookup_prefix = normalize_lookup_prefix(options.lookup_prefix)
    if options.root is not None:
        root = options.root.resolve(strict=True)
        entries = inventory_tree(root)
    else:
        entries = inventory_composefs_dump(options.composefs_dump)
    with FileContextResolver(options.libselinux, options.file_contexts) as resolver:
        labels = plan_labels(
            entries,
            resolver,
            options.dynamic_loader,
            lookup_prefix,
        )
    write_outputs(
        options.file_contexts,
        labels,
        options.output_file_contexts,
        options.output_map,
        lookup_prefix,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PlanError) as error:
        print(f"context-plan: {error}", file=sys.stderr)
        raise SystemExit(1) from error
