"""Emits equivalent native/Rust constants from a declared source value."""

import argparse
import os
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--inputs", nargs=1, type=Path, required=True)
parser.add_argument("--outputs", nargs=2, type=Path, required=True)
options = parser.parse_args()
value = int(options.inputs[0].read_text()) + int(os.environ["AOS_FIXTURE_OFFSET"])
header, rust = options.outputs
header.write_text(f"#define AOS_FIXTURE_VALUE {value}\n")
rust.write_text(f"/// Returns the declared generated value.\npub fn answer() -> u32 {{ {value} }}\n")
