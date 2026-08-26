##! aos-hub-console-dist — browser assets for the typed Hub management console.
##!
##! Builds the Leptos CSR application hermetically for `wasm32-unknown-unknown`
##! and runs the version-locked AOS `wasm-bindgen-cli` with its `web` target.
##! Native Hub and Worker packages consume these exact bytes, preserving one
##! browser application across both deployment runtimes.
{
  lib,
  mkDerivation,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
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
      base
      != "target"
      && base != ".git"
      && (
        pathString
        == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString
      );
  };
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-J3s3XqW8nz1YeU3towJTdnv6WVxP4R8CzRUFPG0Rtrk=";
  };
  cargoEnv = {PROTOC = "${protobuf}/bin/protoc";};
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-hub-console-wasm-artifacts";
    inherit version cargoDeps cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-hub-console-wasm-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoFlags = "-p aos-hub-console --target wasm32-unknown-unknown";
    cargoArtifactContract = {
      family = "aos-hub-console-wasm-release";
      target = "wasm32-unknown-unknown";
      nativeInputs = map toString [protobuf stdenv.cc];
    };
    buildDeps = [protobuf stdenv.cc];
  };
in
  mkDerivation {
    pname = "aos-hub-console-dist";
    inherit version src;

    buildDeps = [rust wasm-bindgen-cli protobuf stdenv.cc];
    inherit cargoDeps;

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
          sed "s|@vendor@|$cargoDeps|g" "$cargoDeps/.cargo/config.toml" \
            > .cargo/config.toml
          export PROTOC="${protobuf}/bin/protoc"
          mkdir -p target
          tar xf ${cargoArtifacts}/target.tar -C target
          chmod -R u+w target
          find . -path ./target -prune -o -type f -name '*.rs' -exec touch {} +
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
          test -s "$out/hub-console.js"
          test -s "$out/hub-console_bg.wasm"
          test -s "$out/hub-console.css"
          grep -q 'export function mount' "$out/hub-console.js"
          grep -q 'var(--paper)' "$out/hub-console.css"
          grep -q 'var(--form-label-col)' "$out/hub-console.css"
          if grep -Eq ':root|color-scheme:|--canvas:|font-family: system-ui|box-shadow:|backdrop-filter:' "$out/hub-console.css"; then
            echo "management console CSS must extend, not replace, the shared Hub design" >&2
            exit 1
          fi
          printf '\0asm' > "$TMPDIR/wasm-magic"
          head -c 4 "$out/hub-console_bg.wasm" > "$TMPDIR/wasm-prefix"
          cmp "$TMPDIR/wasm-magic" "$TMPDIR/wasm-prefix"
        '';
      }
    ];

    meta = {
      description = "Browser assets for the typed AOS Hub management console";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
