"""Use the source-built cargo-bazel generator without a Bazel download.

The dependency snapshot is fetched with network access, but the final workerd
build runs with Bazel downloads disabled. rules_rust still calls download() for
a file:// URL in that phase, so direct the module extension to the pinned Nix
store executable instead.
"""

import argparse
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("extension", type=Path)
args = parser.parse_args()

source = args.extension.read_text()
marker = '    output = module_ctx.path("cargo-bazel.exe" if "win" in module_ctx.os.name else "cargo-bazel")'
assert source.count(marker) == 1, "rules_rust generator source changed"

replacement = '''    if generator_url.startswith("file://"):
        return module_ctx.path(generator_url[7:])

''' + marker
args.extension.write_text(source.replace(marker, replacement))
