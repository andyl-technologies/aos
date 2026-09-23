"""Prepare the pinned Pyodide tree for an offline AOS source build."""

import os
from pathlib import Path
import shutil
import tarfile
import zipfile


def replace_once(path, old, new):
    """Reject upstream drift instead of silently leaving network recipes intact."""
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"Expected one matching recipe in {path}: {old}")
    path.write_text(text.replace(old, new))


root = Path.cwd()
shell = os.environ["CONFIG_SHELL"]
emscripten = Path(os.environ["PYODIDE_EMSCRIPTEN"])
binaryen = Path(os.environ["PYODIDE_BINARYEN"])
python = os.environ["PYODIDE_BUILD_PYTHON"]

replace_once(Path("Makefile.envs"), "SHELL := /usr/bin/env bash", f"SHELL := {shell}")
Path("pyodide_env.sh").write_text(
    f'export EM_CONFIG="{emscripten}/libexec/emscripten/aos-config.py"\n'
    f'export EM_DIR="{emscripten}/libexec/emscripten"\n'
    'unset _EMCC_CCACHE\n'
)
sdk = Path("emsdk/emsdk")
(sdk / "upstream/bin").mkdir(parents=True)
(sdk / "emsdk_env.sh").write_text(Path("pyodide_env.sh").read_text())
(sdk / "upstream/bin/wasm-as").symlink_to(binaryen / "bin/wasm-as")
(sdk / ".complete").touch()

# Keep SQLite bound to the Wasm library built by this source tree, just as
# the adjacent lzma/zstd module definitions already do.
replace_once(
    Path("cpython/Setup.local"),
    "_sqlite/util.c -lsqlite3",
    "_sqlite/util.c -I../sqlite3/dist/include -L../sqlite3/dist/lib -lsqlite3",
)

downloads = Path("cpython/downloads")
downloads.mkdir()
shutil.copyfile(os.environ["PYODIDE_PYTHON_SRC"], downloads / "Python-3.14.2.tgz")
makefile = Path("cpython/Makefile")
# Configure generates both outputs in one invocation. Declare the group so a
# fresh parallel build does not require pyconfig.h before configure completes.
replace_once(
    makefile,
    "$(PYBUILD)/Makefile: $(PYBUILD)/.patched",
    "$(PYBUILD)/Makefile $(PYBUILD)/pyconfig.h &: $(PYBUILD)/.patched",
)
# Installation-time Makefile edits and sysconfig generation consume the
# completed library build, rather than racing configure or compilation.
replace_once(makefile, "sysconfigdata:\n", "sysconfigdata: $(PYBUILD)/$(PYLIB)\n")
replace_once(
    makefile,
    "$(PYBUILD)/.patched_makefile:\n",
    "$(PYBUILD)/.patched_makefile: $(PYBUILD)/$(PYLIB)\n",
)

# Both Autoconf projects otherwise try to execute Wasm as a native program.
configure_command = "&& emconfigure ./configure"
configure_replacement = (
    f"&& emconfigure {shell} ./configure "
    f"--build={os.environ['PYODIDE_BUILD_TRIPLE']} --host=wasm32-unknown-emscripten"
)
text = makefile.read_text()
if text.count(configure_command) != 2:
    raise RuntimeError("Expected xz and SQLite configure recipes")
makefile.write_text(text.replace(configure_command, configure_replacement))

for name, variable in [("libffi", "LIBFFI"), ("hiwire", "HIWIRE")]:
    old = (
        "&& git init \\\n\t\t"
        f"&& git fetch --depth 1 $({variable}REPO) $({variable}_COMMIT) \\\n\t\t"
        "&& git checkout FETCH_HEAD"
    )
    source = os.environ[f"PYODIDE_{name.upper()}_SRC"]
    replace_once(makefile, old, f"&& tar xf {source} --strip-components=1")

for name, variable in [("xz", "LZMA"), ("zstd", "ZSTD"), ("sqlite", "SQLITE3")]:
    source = os.environ[f"PYODIDE_{name.upper()}_SRC"]
    replace_once(
        makefile,
        f"wget -q -O - $({variable}TARBALL) | tar -xz --strip-components=1",
        f"tar xf {source} --strip-components=1",
    )
# The pinned xz release predates Emscripten triplets. CPython's pinned
# config.sub already recognizes the target and is available after prepare-source.
xz_source = os.environ["PYODIDE_XZ_SRC"]
replace_once(
    makefile,
    f"tar xf {xz_source} --strip-components=1",
    f"tar xf {xz_source} --strip-components=1 && cp $(PYBUILD)/config.sub build-aux/config.sub",
)
replace_once(
    makefile,
    "CC=emcc EMSCRIPTEN_DEDUPLICATE=1 EXTERN_FAIL=1 make",
    f"CC=emcc EMSCRIPTEN_DEDUPLICATE=1 EXTERN_FAIL=1 make SHELL={shell}",
)
replace_once(makefile, "./testsuite/emscripten/build.sh", f"{shell} ./testsuite/emscripten/build.sh")
replace_once(makefile, "\t\t  ./configure \\\n", f"\t\t  {shell} ./configure \\\n")
replace_once(makefile, "--build=$(shell $(PYBUILD)/config.guess)", "--build=" + os.environ["PYODIDE_BUILD_TRIPLE"])

modules = Path("src/js/node_modules")
modules.mkdir()
(modules / "esbuild").symlink_to(Path(os.environ["PYODIDE_ESBUILD"]) / "lib/node_modules/esbuild")
replace_once(Path("Makefile"), "cd src/js && npm ci", "test -f src/js/node_modules/esbuild/lib/main.js")
# Execute the exact upstream build-inner script without npm's env shebang.
replace_once(
    Path("Makefile"),
    "cd src/js && npm run build-inner && cd -",
    "node src/js/esbuild.config.inner.mjs",
)
replace_once(Path("Makefile"), "./tools/create_zipfile.py", f"{python} tools/create_zipfile.py")

# Emscripten accepts already-unpacked ports when their upstream URL marker
# matches. All bytes come from Nix's hash-verified source inputs.
ports = Path(os.environ["EM_PORTS"])
port_sources = [
    ("bzip2", "https://github.com/emscripten-ports/bzip2/archive/1.0.6.zip"),
    ("zlib", "https://github.com/madler/zlib/archive/refs/tags/v1.3.1.tar.gz"),
]
for name, url in port_sources:
    destination = ports / name
    destination.mkdir(parents=True)
    source = os.environ[f"PYODIDE_{name.upper()}_SRC"]
    if name == "bzip2":
        with zipfile.ZipFile(source) as archive:
            archive.extractall(destination)
    else:
        with tarfile.open(source) as archive:
            archive.extractall(destination, filter="data")
    (destination / ".emscripten_url").write_text(url + "\n")
