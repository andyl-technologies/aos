##! Emscripten toolchain used to build Pyodide's embedded runtime from source.
{
  mkDerivation,
  fetchurl,
  callPackage,
  buildPackages,
  python3,
  nodejs,
  bash,
  coreutils,
  ninja,
  cmake,
  gnumake,
}: let
  llvm = callPackage ./_emscripten-llvm.nix {};
  binaryen = callPackage ./_binaryen.nix {};
  acorn = callPackage ./_emscripten-acorn.nix {};
  pyodide = fetchurl {
    urls = ["https://github.com/pyodide/pyodide/archive/refs/tags/314.0.0.tar.gz"];
    hash = "12kdn18dcz4kvl5284lz6jwz2grdmi49m9rgd37wb57zldjidak8";
  };
in
  mkDerivation {
    pname = "pyodide-emscripten";
    version = "5.0.3";
    src = fetchurl {
      urls = ["https://github.com/emscripten-core/emscripten/archive/refs/tags/5.0.3.tar.gz"];
      hash = "0q0k4lj3qk1m8c5270gw17l8mb56grxwdvmi0rdz24mf5ccy8b5k";
    };
    buildDeps = [buildPackages.python3 buildPackages.patch];
    runtimeDeps = [llvm binaryen acorn python3 nodejs bash coreutils ninja cmake gnumake];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          tar xf ${pyodide} pyodide-314.0.0/emsdk/patches
          cd emscripten-5.0.3
          for patch_file in ../pyodide-314.0.0/emsdk/patches/*.patch; do
            patch -p1 < "$patch_file"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/libexec/emscripten" "$out/bin" "$out/share/licenses/pyodide-emscripten"
          cp -R . "$out/libexec/emscripten/"
          cd "$out/libexec/emscripten"
          # Test fixtures and the Windows launcher are prebuilt executables,
          # neither of which belongs in this Linux build-tool installation.
          rm -rf test tools/pylauncher
          mkdir -p node_modules
          ln -s ${acorn}/lib/node_modules/acorn node_modules/acorn

          cat > "$out/libexec/emscripten/aos-config.py" <<'CONFIG'
          import os
          LLVM_ROOT = '${llvm}/bin'
          BINARYEN_ROOT = '${binaryen}'
          NODE_JS = ['${nodejs}/bin/node']
          CACHE = os.path.join(os.environ.get('XDG_CACHE_HOME', os.path.expanduser('~/.cache')), 'aos-emscripten', '5.0.3')
          CONFIG

          ${buildPackages.python3}/bin/python3 <<'PY'
          from pathlib import Path
          import os
          import runpy

          root = Path.cwd()
          output = Path(os.environ['out'])
          entrypoints = runpy.run_path('tools/maint/create_entry_points.py')
          names = entrypoints['compiler_entry_points'] + entrypoints['entry_points']
          for name in names:
              if name.startswith('test/'):
                  continue
              target = entrypoints['entry_remap'].get(name, name)
              wrapper = root / name
              wrapper.write_text(
                  '#!${bash}/bin/bash\n'
                  'unset _PYTHON_SYSCONFIGDATA_NAME\n'
                  f'export EM_CONFIG="{root}/aos-config.py"\n'
                  f'exec ${python3}/bin/python3 -E "{root}/{target}.py" "$@"\n'
              )
              wrapper.chmod(0o755)
              if name.startswith('em') and '/' not in name:
                  (output / 'bin' / name).symlink_to(wrapper)
          PY
          cp LICENSE "$out/share/licenses/pyodide-emscripten/"
        '';
      }
      {
        name = "check";
        script = ''
          export EM_CACHE="$NIX_BUILD_TOP/emscripten-cache"
          cd "$NIX_BUILD_TOP"
          printf '%s\n' '#include <stdio.h>' 'int main(void) { puts("aos-wasm-ok"); return 0; }' > check.c
          "$out/bin/emcc" check.c -O2 -o check.js
          ${nodejs}/bin/node check.js > check.stdout
          test "$(cat check.stdout)" = aos-wasm-ok
        '';
      }
    ];
    passthru.evidenceSources = [pyodide];
    meta = {
      description = "Source-built Emscripten compiler for Pyodide";
      homepage = "https://emscripten.org/";
      license = "MIT OR NCSA";
    };
  }
