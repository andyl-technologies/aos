"""Rejects any offset or fuzz in an original native source application log."""

from pathlib import Path
import re
import sys

if sys.flags.optimize:
    raise RuntimeError('Optimized evidence execution refuses')
if re.search(rb'\b(offset|fuzz)\b', Path(sys.argv[1]).read_bytes(), re.I):
    raise ValueError('Original native source did not apply exactly')
