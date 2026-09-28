"""Select the AOS cross target toolchain while retaining native generators."""

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
parser.add_argument("--repository-name", default="aos_arm64_toolchain")
parser.add_argument("--target-os", choices=("linux", "darwin"), default="linux")
args = parser.parse_args()
if not args.toolchain.is_absolute() or not (args.toolchain / "BUILD.bazel").is_file():
    raise RuntimeError("Expected an installed AOS cross Bazel toolchain")

configuration = Path(".bazelrc")
contents = configuration.read_text()
for old, new in [
    ("--cxxopt='-stdlib=libc++'", "--cxxopt='-stdlib=libstdc++'"),
    ("--linkopt='-stdlib=libc++'", "--linkopt='-stdlib=libstdc++'"),
    ("--linkopt='-l:libc++.a'", ""),
    ("--linkopt='-static-libgcc'", ""),
]:
    if args.target_os == "darwin" and old in {
        "--cxxopt='-stdlib=libc++'",
        "--linkopt='-stdlib=libc++'",
    }:
        continue
    contents = replace_exact(contents, old, new)

if args.target_os == "darwin":
    # Linux remains the execution platform. Remove its target ELF linker
    # flags and retain the host options for native generators.
    contents = replace_exact(contents, '--linkopt="-Wl,--gc-sections"', "")
    contents += "\nbuild --config=macos\n"
    # Compile-cache generation executes during the build, just like V8's
    # generators. Keep the source-built generator on the execution platform.
    bundle_rule = Path("build/wd_js_bundle.bzl")
    bundle_rule.write_text(replace_exact(
        bundle_rule.read_text(),
        'cfg = "target",\n            default = "//src/rust/gen-compile-cache",',
        'cfg = "exec",\n            default = "//src/rust/gen-compile-cache",',
    ))
configuration.write_text(contents)

# Native generators retain their Linux toolchain; the target uses the cross
# compiler and source-built runtime selected by the explicit platform.
with Path("MODULE.bazel").open("a") as module:
    module.write('\naos_cross_repo = use_repo_rule("@bazel_tools//tools/build_defs/repo:local.bzl", "local_repository")\n')
    module.write("aos_cross_repo(\n")
    module.write(f"    name = {json.dumps(args.repository_name)},\n")
    module.write(f"    path = {json.dumps(str(args.toolchain))},\n")
    module.write(")\n")
