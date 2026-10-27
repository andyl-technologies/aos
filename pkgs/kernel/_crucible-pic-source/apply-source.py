"""Applies the bounded PIC source prerequisites without fuzz or offset.

The input is the exact Stage7 tree. This constructs object-check source inputs,
not a complete runnable kernel, hardware qualification or board permission.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

MAXIMUM_FILES = 128
MAXIMUM_BYTES = 64 * 1024**2


def identity(path):
    body = path.read_bytes()
    return {'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}


def verify(root, rows, phase):
    total = 0
    for row in rows:
        relative = PurePosixPath(row['path'])
        if relative.is_absolute() or '..' in relative.parts or str(relative) != row['path']:
            raise ValueError('Noncanonical native source role')
        path = root / row['path']
        expected = row[phase]
        if expected is None:
            if path.exists():
                raise ValueError('Unexpected source before its original addition')
            continue
        if not path.is_file() or identity(path) != expected:
            raise ValueError('Changed original source input: ' + row['path'])
        total += expected['bytes']
        if total > MAXIMUM_BYTES:
            raise ValueError('Native source reservation exceeds its bound')


def main():
    if sys.flags.optimize:
        raise RuntimeError('Optimized evidence execution refuses')
    root = Path(sys.argv[1]).resolve()
    patch_tool = sys.argv[2]
    here = Path(__file__).parent
    rows = json.loads((here / 'source-inventory.json').read_text())['files']
    if len(rows) > MAXIMUM_FILES:
        raise ValueError('Native source role reservation exceeds its bound')
    verify(root, rows, 'stage7')
    for name, phase in [('prerequisite-source.patch', 'prerequisite'),
                        ('pic-component.patch', 'completed')]:
        result = subprocess.run([patch_tool, '--batch', '--fuzz=0', '-p1', '-i',
                                 str((here / name).resolve())], cwd=root,
                                capture_output=True, timeout=30)
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        if result.returncode or re.search(rb'\b(offset|fuzz)\b',
                                         result.stdout + result.stderr, re.I):
            raise ValueError('Native source patch failed exact application')
        verify(root, rows, phase)
    print('Exact native PIC source inputs retained; no runnable-board permission')


if __name__ == '__main__':
    main()
