##! Native LLVM revision selected by the Emscripten 5.0.3 SDK.
{
  callPackage,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  revision = "e5927fecf8a6ce89e1a4eac5b828e7d42676452a";
  mkLlvm = callPackage ../../toolchain/llvm/_llvm.nix {};
  compiler = mkLlvm {
    version = "23.0.0";
    srcHash = "0ribd251cdsvkzm1ykqjd7csiwsiyswn333609s1877mba2pm8gl";
    projects = ["clang" "lld"];
    # Emscripten builds its target C/C++ runtimes separately for WebAssembly.
    runtimes = [];
    targets = ["Native" "WebAssembly"];
    needsArc4randomFix = false;
  };
in
  assert !stdenv.isCross;
    compiler.overrideAttrs (old: {
      pname = "emscripten-llvm";
      src = fetchurl {
        urls = ["https://github.com/llvm/llvm-project/archive/${revision}.tar.gz"];
        hash = "0ribd251cdsvkzm1ykqjd7csiwsiyswn333609s1877mba2pm8gl";
      };
      buildDeps = old.buildDeps ++ [buildPackages.nodejs];
      phases =
        map
        (phase:
          if phase.name == "unpack"
          then
            phase
            // {
              script = ''
                tar xf "$src"
                cd llvm-project-${revision}
              '';
            }
          else phase)
        old.phases
        ++ [
          {
            name = "check-wasm-toolchain";
            script = ''
              printf '%s\n' 'int answer(void) { return 42; }' > check.c
              "$out/bin/clang" --target=wasm32-unknown-unknown -c check.c -o check.o
              "$out/bin/wasm-ld" --no-entry --export=answer check.o -o check.wasm
              ${buildPackages.nodejs}/bin/node <<'JS'
              const assert = require('node:assert/strict');
              const fs = require('node:fs');
              const module = new WebAssembly.Module(fs.readFileSync('check.wasm'));
              const instance = new WebAssembly.Instance(module);
              assert.equal(instance.exports.answer(), 42);
              JS
            '';
          }
        ];
    })
