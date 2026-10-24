"""Apply the selected full-kernel source chain using exact reviewed bytes.

Every original native role is checked before and after every patch. This
policy belongs to the selected full-kernel recipe, not a separate check build.
"""

from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import subprocess
import sys


def identity(path):
    data = path.read_bytes()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def verify(root, rows, inventory):
    if len(rows) > inventory['maximum_files']:
        raise ValueError('Native source role bound exceeded')
    total = 0
    seen = set()
    for row in rows:
        role = PurePosixPath(row['path'])
        if role.is_absolute() or '..' in role.parts or str(role) != row['path'] or role in seen:
            raise ValueError('Noncanonical or repeated native source role')
        seen.add(role)
        path = root / role
        expected = row['identity']
        if path.is_symlink():
            raise ValueError('Native source alias refused')
        if expected is None:
            if path.exists():
                raise ValueError('Native source existed before its original addition')
        elif not path.is_file() or path.stat().st_size != expected['bytes'] or identity(path) != expected:
            raise ValueError('Changed exact native source: ' + row['path'])
        else:
            total += expected['bytes']
    if total > inventory['maximum_source_bytes']:
        raise ValueError('Native source byte bound exceeded')


def main():
    if sys.flags.optimize:
        raise RuntimeError('Optimized source evidence refused')
    root = Path(sys.argv[1]).resolve()
    inventory = json.loads((Path(__file__).resolve().parent / 'kernel-patch-inventory.json').read_text())
    patches = [Path(value) for value in sys.argv[3:]]
    if len(patches) != len(inventory['steps']):
        raise ValueError('Selected source patch count changed')
    # Verify every supplied immutable patch before the first source effect.
    for patch, step in zip(patches, inventory['steps'], strict=True):
        if not patch.is_file() or patch.stat().st_size != step['patch']['bytes'] or identity(patch) != step['patch']:
            raise ValueError('Selected source patch bytes changed: ' + step['name'])
    for patch, step in zip(patches, inventory['steps'], strict=True):
        verify(root, step['before'], inventory)
        result = subprocess.run([sys.argv[2], '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                cwd=root, capture_output=True, timeout=30)
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        if result.returncode or re.search(rb'\b(offset|fuzz)\b', result.stdout + result.stderr, re.I):
            raise ValueError('Selected native source patch was not exact: ' + step['name'])
        verify(root, step['after'], inventory)
    print('Exact selected full-kernel source retained; link/guest/RUN/Ready unqualified')


if __name__ == '__main__':
    main()
