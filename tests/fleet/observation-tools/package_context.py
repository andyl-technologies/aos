"""Read immutable installed helper metadata independently of private captures."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat


MAX_CODE = 512 * 1024 * 1024
INODE_FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def unchanged(before, after):
    return all(getattr(before, name) == getattr(after, name) for name in INODE_FIELDS)


@contextmanager
def open_installed(path, maximum=MAX_CODE):
    """Hold no-follow immutable ancestors and the selected installed file inode."""
    path = Path(path)
    if (not path.is_absolute() or path != path.resolve(strict=True)
            or not re.match(r'^/nix/store/[0-9a-z]{32}-[^/]+/', str(path))):
        raise ValueError('Installed code path is not canonical')
    descriptors = []
    brackets = []
    source = None
    try:
        directory = os.open('/nix/store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        # Store ownership can be mapped in a sandbox. This comparison asserts
        # local store custody, not a claim about the host's numeric root UID.
        store_owner = os.fstat(directory).st_uid
        for component in path.parts[3:-1]:
            directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            descriptors.append(directory)
            before = os.fstat(directory)
            if (not stat.S_ISDIR(before.st_mode) or before.st_uid != store_owner
                    or before.st_mode & 0o222):
                raise ValueError('Installed code ancestor custody differs')
            brackets.append((directory, before))
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        source = os.fdopen(descriptor, 'rb')
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != store_owner
                or before.st_mode & 0o222 or before.st_size > maximum):
            raise ValueError('Installed code custody differs')
        yield source
        if (not unchanged(before, os.fstat(source.fileno()))
                or any(not unchanged(old, os.fstat(fd)) for fd, old in brackets)):
            raise ValueError('Installed code changed')
    finally:
        if source is not None:
            source.close()
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def installed_bytes(path, maximum=MAX_CODE):
    """Read canonical immutable Nix code without relaxing private-file custody."""
    with open_installed(path, maximum) as stream:
        size = os.fstat(stream.fileno()).st_size
        raw = stream.read(maximum + 1)
        if len(raw) != size:
            raise ValueError('Installed code length differs')
    return raw


def context(script):
    """Load the build record next to the actual installed script inode."""
    directory = Path(script).resolve(strict=True).parent
    raw = installed_bytes(directory / 'package-context.json', 1024 * 1024)
    selected = json.loads(raw)
    expected = {'version', 'runtimeSource', 'runtime', 'runtimeProvenance', 'sourceTree', 'nativeAuth',
                'observerExecutable', 'captureImplementationSha256', 'producerSha256'}
    if set(selected) != expected or selected['version'] != 1:
        raise ValueError('Installed helper context differs')
    for reference in (selected['nativeAuth'], selected['observerExecutable']):
        if set(reference) != {'file', 'sha256', 'byteSize'}:
            raise ValueError('Installed code reference differs')
        body = installed_bytes(reference['file'])
        if (hashlib.sha256(body).hexdigest() != reference['sha256']
                or str(len(body)) != reference['byteSize']):
            raise ValueError('Installed code commitment differs')
    if selected['producerSha256'] != {'sdk': None, 'client': None}:
        # This package currently has no compiled SDK ledger producers. Adding
        # them requires selected source/artifact correspondence, not log hashes.
        raise ValueError('Unavailable producer was asserted as installed')
    return selected
