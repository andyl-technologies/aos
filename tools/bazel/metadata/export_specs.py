"""Binds exported crate specifications to their declared source definitions."""

import argparse
import hashlib
import json
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--input", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--contract", nargs=2, action="append", default=[])
options = parser.parse_args()
value = json.loads(options.input.read_text())
value["contracts"] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in options.contract}
options.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
