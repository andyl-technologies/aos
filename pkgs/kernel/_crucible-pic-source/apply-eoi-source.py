"""Applies original EOI ancestry only after the exact completed PIC checkpoint."""

from pathlib import Path
import json
import re
import subprocess
import sys

import importlib.util

MODULE_PATH = Path(__file__).with_name('apply-source.py')
SPEC = importlib.util.spec_from_file_location('pic_exact_source', MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('Missing original exact-source verifier')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
verify = MODULE.verify


def main():
    if sys.flags.optimize:
        raise RuntimeError('Optimized exact-source application refuses')
    root = Path(sys.argv[1]).resolve()
    here = Path(__file__).parent
    rows = json.loads((here / 'source-inventory.json').read_text())['files']
    verify(root, rows, 'completed')
    result = subprocess.run([sys.argv[2], '--batch', '--fuzz=0', '-p1', '-i',
                             str(here / 'pending-eoi-component.patch')],
                            cwd=root, capture_output=True, timeout=30)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    if result.returncode or re.search(rb'\b(offset|fuzz)\b',
                                     result.stdout + result.stderr, re.I):
        raise ValueError('Original EOI source application was not exact')
    verify(root, rows, 'eoi')
    print('Exact EOI source closure retained; FirstBegin remains unsupported')


if __name__ == '__main__':
    main()
