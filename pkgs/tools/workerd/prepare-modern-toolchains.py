"""Bind modern workerd's module extensions to AOS-built host tools."""

import argparse
import json
from pathlib import Path


def replace_exact(path, old, new, count=1):
    """Fail when the pinned upstream module no longer matches the reviewed edit."""
    contents = path.read_text()
    if contents.count(old) != count:
        raise RuntimeError(f"Expected {count} occurrences of {old!r} in {path}")
    path.write_text(contents.replace(old, new))


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--python", required=True, type=Path)
parser.add_argument("--rust", required=True, type=Path)
args = parser.parse_args()

for executable in [args.python, args.rust / "bin/cargo", args.rust / "bin/rustc"]:
    if not executable.is_absolute() or not executable.is_file():
        raise RuntimeError(f"Expected an absolute installed executable: {executable}")

python_module = Path("build/deps/python.MODULE.bazel")
original = '''python = use_extension("@rules_python//python/extensions:python.bzl", "python")
python.toolchain(python_version = "3.13")
use_repo(python, "python_3_13")'''
replacement = f'''aos_python_runtime = use_repo_rule("@rules_python//python/local_toolchains:repos.bzl", "local_runtime_repo")
aos_python_runtime(
    name = "aos_python",
    interpreter_path = {json.dumps(str(args.python))},
)
aos_python_toolchains = use_repo_rule("@rules_python//python/local_toolchains:repos.bzl", "local_runtime_toolchains_repo")
aos_python_toolchains(name = "aos_python_toolchains", runtimes = ["aos_python"])
register_toolchains("@aos_python_toolchains//:all")'''
replace_exact(python_module, original, replacement)
replace_exact(python_module, 'python_version = "3.13"', 'python_version = "3.14"', count=2)
replace_exact(
    python_module,
    "pip.parse(\n",
    f"pip.parse(\n    python_interpreter = {json.dumps(str(args.python))},\n",
    count=2,
)

# crate_universe otherwise downloads host Cargo before analyzing Rust targets.
replace_exact(
    Path("build/deps/rust.MODULE.bazel"),
    "crate.from_cargo(\n",
    'crate.from_cargo(\n    host_tools = "//aos-host-rust:BUILD.bazel",\n',
)
host_tools = Path("aos-host-rust")
(host_tools / "bin").mkdir(parents=True)
(host_tools / "BUILD.bazel").write_text(
    'exports_files(["BUILD.bazel"], visibility = ["//visibility:public"])\n'
)
for executable in ["cargo", "rustc"]:
    (host_tools / "bin" / executable).symlink_to(args.rust / "bin" / executable)
