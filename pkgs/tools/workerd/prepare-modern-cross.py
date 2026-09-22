"""Select the AOS ARM64 target toolchain while retaining native generators."""

import argparse
import json
from pathlib import Path


def replace_exact(contents, old, new):
    """Reject source drift instead of silently retaining native target flags."""
    if contents.count(old) != 1:
        raise RuntimeError(f"Expected one occurrence of {old!r} in .bazelrc")
    return contents.replace(old, new)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--toolchain", required=True, type=Path)
args = parser.parse_args()
if not args.toolchain.is_absolute() or not (args.toolchain / "BUILD.bazel").is_file():
    raise RuntimeError("Expected an installed AOS ARM64 Bazel toolchain")

configuration = Path(".bazelrc")
contents = configuration.read_text()
for old, new in [
    ("--cxxopt='-stdlib=libc++'", "--cxxopt='-stdlib=libstdc++'"),
    ("--linkopt='-stdlib=libc++'", "--linkopt='-stdlib=libstdc++'"),
    ("--linkopt='-l:libc++.a'", ""),
    ("--linkopt='-static-libgcc'", ""),
]:
    contents = replace_exact(contents, old, new)
configuration.write_text(contents)

# The native generator configuration still uses libc++; only the ARM64 target
# uses the standard library supplied by the AOS cross compiler.
with Path("MODULE.bazel").open("a") as module:
    module.write('\naos_cross_repo = use_repo_rule("@bazel_tools//tools/build_defs/repo:local.bzl", "local_repository")\n')
    module.write("aos_cross_repo(\n")
    module.write('    name = "aos_arm64_toolchain",\n')
    module.write(f"    path = {json.dumps(str(args.toolchain))},\n")
    module.write(")\n")
