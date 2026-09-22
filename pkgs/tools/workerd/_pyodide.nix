##! Pyodide runtime embedded by workerd, built entirely from pinned sources.
{
  mkDerivation,
  callPackage,
  buildPackages,
  lib,
  stdenv,
}: let
  sources = callPackage ./_pyodide-sources.nix {};
  emscripten = callPackage ./_emscripten.nix {};
  binaryen = callPackage ./_binaryen.nix {};
  llvm = callPackage ./_emscripten-llvm.nix {};
  esbuild = callPackage ./_pyodide-esbuild.nix {};
  sourceInputs = builtins.removeAttrs sources ["version" "src"];
in
  mkDerivation ({
      pname = "workerd-pyodide";
      inherit (sources) version src;
      buildDeps = [
        emscripten
        buildPackages.python3
        buildPackages.nodejs
        buildPackages.gnumake
        buildPackages.cmake
        buildPackages.pkg-config
        buildPackages.autoconf
        buildPackages.automake
        buildPackages.libtool
        buildPackages.which
        buildPackages.patch
        buildPackages.perl
      ];
      runtimeDeps = [];
      PYODIDE_EMSCRIPTEN = emscripten;
      PYODIDE_BINARYEN = binaryen;
      PYODIDE_ESBUILD = esbuild;
      PYODIDE_BUILD_PYTHON = "${buildPackages.python3}/bin/python3";
      PYODIDE_BUILD_TRIPLE = stdenv.buildPlatform.config;
      phases = [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd pyodide-${sources.version}
          '';
        }
        {
          name = "configure";
          script = ''
            export CONFIG_SHELL=${buildPackages.bash}/bin/bash
            export ACLOCAL_PATH="${buildPackages.libtool}/share/aclocal:${buildPackages.pkg-config}/share/aclocal"
            export EM_CACHE="$NIX_BUILD_TOP/emscripten-cache"
            export EM_PORTS="$NIX_BUILD_TOP/emscripten-ports"
            export PYODIDE_JOBS="$NIX_BUILD_CORES"
            # Host include/library variables must not enter Wasm compilation.
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            ${buildPackages.python3}/bin/python3 ${./prepare-pyodide.py}
          '';
        }
        {
          name = "build";
          script = ''
            make -C cpython prepare-source
            # CPython assumes clang is adjacent to emcc in an emsdk download.
            # Resolve the same compiler explicitly in the source-built SDK.
            ${buildPackages.python3}/bin/python3 - <<'PYTHON'
            from pathlib import Path

            path = Path("cpython/build/Python-3.14.2/Makefile.pre.in")
            contents = path.read_text()
            original = "$$(dirname $$(dirname $(CC)))/bin/clang"
            if contents.count(original) != 1:
                raise RuntimeError("Expected one CPython trampoline compiler reference")
            path.write_text(contents.replace(original, "${llvm}/bin/clang"))
            PYTHON
            make -j "$NIX_BUILD_CORES" dist/pyodide.asm.mjs dist/python_stdlib.zip
          '';
        }
        {
          name = "check";
          script = ''
            # Build the upstream loader only for execution of the core runtime.
            make src/core/jsverror.wasm
            node src/js/esbuild.config.outer.mjs
            node --experimental-wasm-stack-switching ${./check-pyodide.mjs} "$PWD/dist"
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/pyodide" "$out/share/licenses/workerd-pyodide"
            cp dist/pyodide.asm.mjs dist/pyodide.asm.wasm dist/python_stdlib.zip "$out/pyodide/"
            ${buildPackages.python3}/bin/python3 ${./install-pyodide-notices.py}
            # Preserve workerd's repository file labels for the source-built core.
            cat > "$out/BUILD.bazel" <<'BUILD'
            exports_files(glob(["pyodide/*"]))
            BUILD
            touch "$out/REPO.bazel"
          '';
        }
      ];
      passthru.evidenceSources = builtins.attrValues sourceInputs;
      meta = {
        description = "Python WebAssembly runtime for workerd";
        homepage = "https://pyodide.org/";
        license = "MPL-2.0";
      };
    }
    // builtins.listToAttrs (lib.mapAttrsToList (name: source: {
        name = "PYODIDE_${lib.toUpper name}_SRC";
        value = source;
      })
      sourceInputs))
