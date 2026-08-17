##! wasm-bindgen-cli — generates JS/TS bindings for a wasm-bindgen-built wasm
##!
##! Version-locked to the `wasm-bindgen` crate the worker compiles against
##! (see `crates/Cargo.lock`: `wasm-bindgen` 0.2.126). The CLI emits the JS
##! glue that the wasm module's imports/exports are wired against, so a CLI
##! that drifts from the crate version produces bindings that break at
##! runtime. Keep this in lockstep with the locked `wasm-bindgen` version.
{
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
    pname = "wasm-bindgen-cli";
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
