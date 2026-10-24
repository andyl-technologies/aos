# SPDX-License-Identifier: MIT
"""Writes a source-fixed AArch64 ELF containing only NOP and a backward branch."""
import struct
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise ValueError('expected one original output path')
code = struct.pack('<II', 0xD503201F, 0x17FFFFFF)
header = struct.pack('<16sHHIQQQIHHHHHH',
    b'\x7fELF\x02\x01\x01' + bytes(9), 2, 183, 1, 0x10000, 64, 0, 0,
    64, 56, 1, 64, 0, 0)
segment = struct.pack('<IIQQQQQQ', 1, 5, 4096, 0x10000, 0x10000,
    len(code), len(code), 4096)
body = header + segment + bytes(4096 - len(header) - len(segment)) + code
with Path(sys.argv[1]).open('xb') as output:
    output.write(body)
