"""Counts compiler and control output against one finite source-check budget."""

import json
from pathlib import Path
import shutil
import sys

FLOOR = 2 * 1024**3
CEILING = 64 * 1024**2
LEDGER = 'resource-baseline.json'


def files(root):
    return {str(path.relative_to(root)): path.stat().st_size
            for path in root.rglob('*') if path.is_file() and
            path.relative_to(root).parts[0] != LEDGER}


def initialize(root):
    if sys.flags.optimize or (root / LEDGER).exists():
        raise RuntimeError('Changed or optimized resource reservation refuses')
    if shutil.disk_usage(root).free < FLOOR:
        raise RuntimeError('Original source-check disk floor refuses')
    (root / LEDGER).write_text(json.dumps(files(root), sort_keys=True) + '\n')


def check(root):
    if sys.flags.optimize:
        raise RuntimeError('Optimized resource checking refuses')
    original = json.loads((root / LEDGER).read_text())
    current = files(root)
    added = sum(max(0, size - original.get(name, 0))
                for name, size in current.items())
    free = shutil.disk_usage(root).free
    if free < FLOOR or added > CEILING:
        raise RuntimeError('Original aggregate compiler/model resource bound refuses')
    return {'added_bytes': added, 'free_bytes': free,
            'output_ceiling_bytes': CEILING, 'disk_floor_bytes': FLOOR}


if __name__ == '__main__':
    root = Path(sys.argv[2]).resolve()
    if sys.argv[1] == 'initialize':
        initialize(root)
    elif sys.argv[1] == 'check':
        print(json.dumps(check(root), sort_keys=True))
    else:
        raise ValueError('Unknown resource operation')
