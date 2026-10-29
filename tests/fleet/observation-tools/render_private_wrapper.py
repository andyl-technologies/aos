"""Render an owned private adapter wrapper from selected immutable package bytes."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys


def installed(path, maximum):
    """Read a held no-follow file under immutable locally owned store ancestors."""
    path = Path(path)
    if (path != path.resolve(strict=True)
            or not re.fullmatch(r'/nix/store/[0-9a-z]{32}-[^/]+/.+', str(path))):
        raise ValueError('Noncanonical installed path')
    descriptors, brackets = [], []
    try:
        directory = os.open('/nix/store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        owner = os.fstat(directory).st_uid
        for part in path.parts[3:-1]:
            directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            descriptors.append(directory)
            info = os.fstat(directory)
            if info.st_uid != owner or info.st_mode & 0o222:
                raise ValueError('Mutable installed ancestor')
            brackets.append((directory, info))
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                or before.st_mode & 0o222 or before.st_size > maximum):
            raise ValueError('Installed file custody differs')
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        brackets.append((descriptor, before))
        if len(raw) != before.st_size or any(
                any(getattr(old, key) != getattr(os.fstat(fd), key) for key in fields)
                for fd, old in brackets):
            raise ValueError('Installed file changed')
        return bytes(raw)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def commitment(path, raw):
    return {'file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
            'byteSize': str(len(raw))}


def selected(reference, maximum):
    if set(reference) != {'file', 'sha256', 'byteSize'}:
        raise ValueError('Installed reference shape differs')
    raw = installed(reference['file'], maximum)
    if commitment(reference['file'], raw) != reference:
        raise ValueError('Installed reference differs')
    return raw


def render(provenance_file, provenance_sha256, output):
    provenance_raw = installed(provenance_file, 1024 * 1024)
    if hashlib.sha256(provenance_raw).hexdigest() != provenance_sha256:
        raise ValueError('Selected provenance differs')
    record = json.loads(provenance_raw)
    if record['version'] != 1 or record['claim'] != 'helper_build_only':
        raise ValueError('Not selected helper build provenance')
    package = Path(provenance_file).parent
    script = package / 'libexec/aos-observation-tools/hosted_assessment.py'
    entry = package / 'bin/aos-hosted-byte-assessment'
    script_ref, = [item for item in record['helperFiles'] if item['file'] == str(script)]
    entry_ref, = [item for item in record['wrappers'] if item['file'] == str(entry)]
    selected(script_ref, 128 * 1024)
    selected(record['context'], 128 * 1024)
    entry_raw = selected(entry_ref, 4096)
    lines = entry_raw.decode('ascii').splitlines()
    if len(lines) != 2 or not lines[0].startswith('#!/nix/store/'):
        raise ValueError('Unsupported installed wrapper')
    arguments = shlex.split(lines[1])
    if (len(arguments) != 6 or arguments[0] != 'exec' or arguments[2:4] != ['-B', '-E']
            or arguments[4] != str(script) or arguments[5] != '$@'):
        raise ValueError('Unsupported installed argument mapping')
    python_alias = Path(arguments[1])
    python = python_alias.resolve(strict=True)
    if python.parent != python_alias.parent or python.name != os.readlink(python_alias):
        raise ValueError('Unsupported installed Python alias')
    python_raw = installed(python, 128 * 1024 * 1024)
    python = str(python)
    argv = [python, '-B', '-E', str(script)]
    body = ('"""Invoke the selected immutable adapter; preserve input and process custody."""\n\n'
            'import os\nimport sys\n\n'
            f'os.execv({python!r}, {argv!r} + sys.argv[1:])\n').encode()

    output = Path(output)
    if not output.is_absolute() or output.parent != output.parent.resolve(strict=True):
        raise ValueError('Noncanonical private output directory')
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(directory)
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700:
            raise ValueError('Output directory is not owned private custody')
        descriptor = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
            info = os.fstat(stream.fileno())
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size != len(body)
                or output.parent.stat().st_ino != before.st_ino
                or output.parent.stat().st_dev != before.st_dev):
            raise ValueError('Private wrapper custody changed')
    finally:
        os.close(directory)
    return {'version': 1, 'claim': 'private_invocation_mapping_only',
            'provenance': commitment(provenance_file, provenance_raw),
            'wrapper': commitment(output, body), 'python': commitment(python, python_raw),
            'installedPythonAlias': {'file': str(python_alias), 'target': Path(python).name},
            'adapter': script_ref, 'argvPrefix': argv,
            'runtimeProvenance': record['runtimeInputs']['runtimeProvenance'],
            'inputArguments': 'unchanged', 'processGroup': 'inherited',
            'inheritedDescriptors': 'unchanged', 'acceptanceClaim': None}


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('Expected installed provenance, selected SHA256 and fresh private output')
    print(json.dumps(render(*sys.argv[1:]), sort_keys=True))
