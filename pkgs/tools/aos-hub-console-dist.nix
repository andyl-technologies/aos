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
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  repoRoot = ../..;
  repoRootString = toString repoRoot;

  # Protobuf and the C toolchain execute on Linux while producing the
  # target-independent WebAssembly distribution.
  buildProtobuf = buildPackages.protobuf;
  buildCc = buildPackages.cc;
  nativeRustTarget = stdenv.buildPlatform.config;
  nativeRustCargoPrefix = lib.toUpper (builtins.replaceStrings ["-"] ["_"] nativeRustTarget);
  nativeRustCcPrefix = builtins.replaceStrings ["-"] ["_"] nativeRustTarget;
  nativeRustToolchain = buildPackages.mkDerivation {
    pname = "aos-hub-console-native-rust-toolchain";
    version = "0";
    src = null;
    runtimeDeps = [buildCc];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"

          write_wrapper() {
            tool=$1
            wrapper=$2
            {
              printf '%s\n' '#!${buildPackages.bash}/bin/bash'
              printf '%s\n' \
                'unset AOS_CROSS_COMPILING AOS_GOARCH AOS_GOOS' \
                'unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE' \
                'unset AOS_OBJECT_FORMAT AOS_RUST_TARGET' \
                'unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM' \
                'unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH' \
                'unset LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET SDKROOT' \
                'unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS'
              printf 'exec %s "$@"\n' "$tool"
            } > "$out/bin/$wrapper"
            chmod +x "$out/bin/$wrapper"
          }

          write_wrapper ${buildCc}/bin/cc cc
          write_wrapper ${buildCc}/bin/c++ c++
          write_wrapper ${buildCc}/bin/ar ar
          write_wrapper ${buildCc}/bin/ranlib ranlib
        '';
      }
    ];
  };
  nativeRustToolchainEnv = lib.optionalAttrs stdenv.isCross {
    "CARGO_TARGET_${nativeRustCargoPrefix}_LINKER" = "${nativeRustToolchain}/bin/cc";
    "CARGO_TARGET_${nativeRustCargoPrefix}_AR" = "${nativeRustToolchain}/bin/ar";
    "CC_${nativeRustCcPrefix}" = "${nativeRustToolchain}/bin/cc";
    "CXX_${nativeRustCcPrefix}" = "${nativeRustToolchain}/bin/c++";
    "AR_${nativeRustCcPrefix}" = "${nativeRustToolchain}/bin/ar";
    "RANLIB_${nativeRustCcPrefix}" = "${nativeRustToolchain}/bin/ranlib";
  };
  mkHubDerivation = args: mkDerivation (args // nativeRustToolchainEnv // consoleReleaseEnv);
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
    hash = "sha256-yf/Gu30exf9weCOK6RRrjusN+bXZ6rj1r+tZbEJMy4g=";
  };
  # Optimize the browser download without changing native Hub or CLI profiles.
  # Keep dependency artifacts and the final application on the same profile.
  consoleReleaseEnv = {
    CARGO_PROFILE_RELEASE_OPT_LEVEL = "s";
    CARGO_PROFILE_RELEASE_LTO = "thin";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
    CARGO_PROFILE_RELEASE_STRIP = "debuginfo";
  };
  cargoEnv = {PROTOC = "${buildProtobuf}/bin/protoc";} // consoleReleaseEnv;
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
      releaseProfile = consoleReleaseEnv;
      target = "wasm32-unknown-unknown";
      nativeInputs = map toString [buildProtobuf buildCc];
    };
    buildDeps = [buildProtobuf buildCc];
  };
in
  mkHubDerivation {
    pname = "aos-hub-console-dist";
    inherit version src;

    buildDeps = [rust wasm-bindgen-cli buildProtobuf buildCc];
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
          export PROTOC="${buildProtobuf}/bin/protoc"
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
          export PROTOC="${buildProtobuf}/bin/protoc"
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
