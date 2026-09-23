"""Remove unused downloaded executables after selecting AOS toolchains.

Source archives and upstream binary test fixtures remain intact. Configured
build tools must come from the explicit source-built repository overrides.
"""

import argparse
import shutil
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("external", type=Path)
args = parser.parse_args()
external = args.external.resolve(strict=True)

# The rules_rust release bundles generators for several host platforms. The
# module extension uses CARGO_BAZEL_GENERATOR_URL pointing to our source build.
for generator in (external / "rules_rust+").glob("*/cargo-bazel*"):
    if generator.is_file() and not generator.is_symlink():
        generator.unlink()

# Overrides make the upstream utility downloads unnecessary. Dropping cached
# executables also prevents an accidental fallback from succeeding offline.
executable_headers = {
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
}
cache = external / "repository_cache/content_addressable"
for payload in cache.glob("*/*/file"):
    with payload.open("rb") as stream:
        header = stream.read(4)
    if header in executable_headers or header[:2] == b"MZ":
        shutil.rmtree(payload.parent)
