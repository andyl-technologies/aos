##! aos-hub-console-dist — browser assets for the typed Hub management console.
##!
##! Builds the Leptos CSR application hermetically for `wasm32-unknown-unknown`
##! and runs the version-locked AOS `wasm-bindgen-cli` with its `web` target.
##! Native Hub and Worker packages consume these exact bytes, preserving one
##! browser application across both deployment runtimes.
{
  lib,
  mkDerivation,
  fetchCargoDeps,
  rust,
  wasm-bindgen-cli,
  protobuf,
  stdenv,
}: let
  version = "0.1.0";
  repoRoot = ../..;
  repoRootString = toString repoRoot;
  src = builtins.path {
    path = repoRoot;
    name = "aos-hub-console-workspace-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base != "target"
      && base != ".git"
      && (
        pathString == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString
      );
  };
in
  mkDerivation {
    pname = "aos-hub-console-dist";
    inherit version src;

    buildDeps = [rust wasm-bindgen-cli protobuf stdenv.cc];
    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
    };

    phases = [
      {
        name = "unpack";
        script = ''
          cp -r "$src" source
          chmod -R u+w source
          cd source/crates
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n\n' \
            "$cargoDeps" > .cargo/config.toml
          export PROTOC="${protobuf}/bin/protoc"
        '';
      }
      {
        name = "build";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          export PROTOC="${protobuf}/bin/protoc"
          cargo build -p aos-hub-console --target wasm32-unknown-unknown \
            --release --frozen --offline -j"$NIX_BUILD_CORES"
          mkdir -p generated
          wasm-bindgen --target web --no-typescript --out-dir generated \
            --out-name hub-console \
            target/wasm32-unknown-unknown/release/aos_hub_console.wasm
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp generated/hub-console.js "$out/hub-console.js"
          cp generated/hub-console_bg.wasm "$out/hub-console_bg.wasm"
          cp aos-hub-console/assets/app.css "$out/hub-console.css"
        '';
      }
    ];

    meta = {
      description = "Browser assets for the typed AOS Hub management console";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
