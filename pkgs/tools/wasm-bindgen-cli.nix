##! wasm-bindgen-cli — generates JS/TS bindings for a wasm-bindgen-built wasm
##!
##! Version-locked to the `wasm-bindgen` crate the worker compiles against
##! (see `crates/Cargo.lock`: `wasm-bindgen` 0.2.126). The CLI emits the JS
##! glue that the wasm module's imports/exports are wired against, so a CLI
##! that drifts from the crate version produces bindings that break at
##! runtime. Keep this in lockstep with the locked `wasm-bindgen` version.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}: let
  version = "0.2.126";
  src = fetchurl {
    # The published `wasm-bindgen-cli` crate is a self-contained package with
    # its own Cargo.lock (unlike the rustwasm/wasm-bindgen git tree, which
    # ships no lockfile). The `.crate` archive is a gzip tarball; name it
    # `.tar.gz` so the generic unpack phase recognises it. The flat output
    # hash is over the raw bytes, so the rename does not affect it.
    name = "wasm-bindgen-cli-${version}.tar.gz";
    urls = [
      "https://static.crates.io/crates/wasm-bindgen-cli/wasm-bindgen-cli-${version}.crate"
    ];
    hash = "sha256-ji6/bu+Hw05mI0fx3d++pUEwS7cpRxHtLCrNh0bMW1A=";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "wasm-bindgen-cli";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Wasm2es6js emits JavaScript containing the encoded WebAssembly module.";
        "files" = {};
        "input" = "A minimal valid WebAssembly module containing only its header and version.";
        "operation" = "Convert the module to an ES module with an inline base64 payload.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\npathlib.Path(\"empty.wasm\").write_bytes(bytes.fromhex(\"0061736d01000000\"))\nresult = subprocess.run([\"@out@/bin/wasm2es6js\", \"--base64\", \"empty.wasm\", \"--output\", \"module.js\"], capture_output=True)\nassert result.returncode == 0, result.stderr\njavascript = pathlib.Path(\"module.js\").read_text()\nassert \"const base64\" in javascript and \"WebAssembly.instantiate\" in javascript\nprint(\"wasm-bindgen-cli operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "wasm-bindgen-cli operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Wasm2es6js rejects the malformed binary and emits no JavaScript module.";
        "files" = {
          "invalid.wasm" = "bad";
        };
        "input" = "A truncated file without the WebAssembly magic header.";
        "operation" = "Attempt to convert the malformed module to JavaScript.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/wasm2es6js\", \"--base64\", \"invalid.wasm\", \"--output\", \"invalid.js\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unexpected end-of-file\" in result.stderr\nassert not pathlib.Path(\"invalid.js\").exists()\n\nsys.stderr.write(\"wasm-bindgen-cli rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "wasm-bindgen-cli rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-H6YeIhMOGSroQA79JUTNTPr/jJ+qlL7j/tzftUXN85U=";
    };

    doCheck = false;

    meta = {
      description = "Generate JS bindings for a wasm-bindgen-built wasm module";
      homepage = "https://github.com/rustwasm/wasm-bindgen";
      license = "MIT OR Apache-2.0";
      mainProgram = "wasm-bindgen";
    };
  }
