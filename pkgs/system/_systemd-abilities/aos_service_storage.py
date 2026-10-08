"""Preserves manager-private service storage during durable retirement.

Only authored standard directory aliases are eligible. Directory-relative
operations reject intermediate links, and intent pins identities only while a
single handoff is pending, never across unrelated service realizations.
"""

from contextlib import contextmanager
import ctypes
import os
from pathlib import Path
import stat

from aos_service_resources import absolute


# DynamicUser retains these directories behind manager-created private aliases.
# RuntimeDirectory has no persistent private backing to transfer on retirement.
PRIVATE_DIRECTORY_ROOTS = {
    "/var/lib/": Path("/var/lib"),
    "/var/cache/": Path("/var/cache"),
    "/var/log/": Path("/var/log"),
}


def private_storage_sources(value):
    if not (value.get("identity") or {}).get("ephemeral", False):
        return []
    sources = []
    for directory in (value.get("logging") or {}).get("directories", []):
        source = "/var/log/" + directory
        storage_paths(source)
        sources.append(source)
    for entry in (value.get("storage") or {}).get("mounts", []):
        if entry.get("ownership") != "service-identity":
            continue
        source = absolute(entry["source"])
        if any(source.startswith(prefix) for prefix in PRIVATE_DIRECTORY_ROOTS):
            storage_paths(source)
            sources.append(source)
    return outermost_sources(sources)


def outermost_sources(sources):
    # An ancestor move carries all nested mounts, including their contents.
    selected = []
    for source in sorted(set(sources), key=lambda path: (len(Path(path).parts), path)):
        if not any(Path(parent) in Path(source).parents for parent in selected):
            selected.append(source)
    return selected


def storage_paths(source):
    """Derives only standard manager-private counterparts of authored paths."""
    source = absolute(source)
    for prefix, root in PRIVATE_DIRECTORY_ROOTS.items():
        if source.startswith(prefix):
            relative = Path(source[len(prefix):])
            if str(Path(source)) != source or not relative.parts or relative.parts[0] == "private":
                raise ValueError("private storage requires a canonical public managed directory")
            return root / relative, root / "private" / relative
    raise ValueError("private storage requires a standard managed directory")


def open_directory_nofollow(path):
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in Path(path).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def storage_parents(source):
    public, backing = storage_paths(source)
    descriptors = []
    try:
        for parent in (public.parent, backing.parent):
            try:
                descriptors.append(open_directory_nofollow(parent))
            except FileNotFoundError:
                descriptors.append(None)
        yield public, backing, *descriptors
    finally:
        for descriptor in descriptors:
            if descriptor is not None:
                os.close(descriptor)


def directory_entry(parent, name):
    if parent is None:
        return None
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def entry_identity(metadata):
    return [metadata.st_dev, metadata.st_ino]


def expected_alias(public, backing, parent):
    return os.readlink(public.name, dir_fd=parent) in {
        str(backing), os.path.relpath(backing, public.parent),
    }


def plan_handoffs(sources):
    """Authenticates all aliases before publishing any destructive intent."""
    records = []
    for source in outermost_sources(sources):
        with storage_parents(source) as (public, backing, public_parent, backing_parent):
            visible = directory_entry(public_parent, public.name)
            private = directory_entry(backing_parent, backing.name)
            if private is not None and not stat.S_ISDIR(private.st_mode):
                raise ValueError("service private storage backing is not a real directory")
            if visible is not None and stat.S_ISLNK(visible.st_mode):
                if not expected_alias(public, backing, public_parent) or private is None:
                    raise ValueError("service private storage alias changed outside its manager")
                records.append({
                    "source": source,
                    "backing_identity": entry_identity(private),
                    "alias_identity": entry_identity(visible),
                })
            elif private is not None or (visible is not None and not stat.S_ISDIR(visible.st_mode)):
                raise ValueError("service private storage conflicts with public contents")
    return records


def checked_handoff_state(record, public, backing, public_parent, backing_parent):
    visible = directory_entry(public_parent, public.name)
    private = directory_entry(backing_parent, backing.name)
    if private is not None:
        if not stat.S_ISDIR(private.st_mode) or entry_identity(private) != record["backing_identity"]:
            raise ValueError("service private storage backing identity changed")
        if visible is None:
            return "unlinked"
        if (stat.S_ISLNK(visible.st_mode)
                and entry_identity(visible) == record["alias_identity"]
                and expected_alias(public, backing, public_parent)):
            return "alias"
    elif (visible is not None and stat.S_ISDIR(visible.st_mode)
            and entry_identity(visible) == record["backing_identity"]):
        return "complete"
    raise ValueError("service private storage handoff conflicts with external changes")


def handoff_state(record):
    """Recognizes original aliases and both durable rename recovery states."""
    with storage_parents(record["source"]) as parents:
        return checked_handoff_state(record, *parents)


def rename_directory_noreplace(source_parent, source, destination_parent, destination):
    # Plain rename may replace an externally created empty directory. Linux's
    # no-replace operation preserves that competing namespace entry instead.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_parent, os.fsencode(source), destination_parent, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def complete_handoff(record):
    with storage_parents(record["source"]) as parents:
        public, backing, public_parent, backing_parent = parents
        state = checked_handoff_state(record, *parents)
        if state == "alias":
            os.unlink(public.name, dir_fd=public_parent)
            os.fsync(public_parent)
        # Keep the authenticated parent descriptors throughout mutation. Check
        # again after durable alias removal before moving the pinned backing.
        state = checked_handoff_state(record, *parents)
        if state != "complete":
            rename_directory_noreplace(backing_parent, backing.name, public_parent, public.name)
        # Repeat these syncs after an interrupted rename before acknowledging it.
        os.fsync(public_parent)
        if backing_parent is not None:
            os.fsync(backing_parent)
