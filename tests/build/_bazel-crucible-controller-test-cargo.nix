##! Captures the ordinary controller's unified release-test compilation graph.
{pkgs}: let
  packages =
    builtins.filter
    (name: !builtins.elem name ["crucible-qemu-plugin" "crucible-qemu-debug-gateway"])
    (import ../../pkgs/tools/crucible/_packages.nix);
  packageFlags = pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) packages);
in
  pkgs.mkDerivation {
    pname = "aos-bazel-crucible-controller-test-cargo";
    version = "1";
    src = import ../../pkgs/tools/crucible/_source.nix {inherit (pkgs) lib;};
    buildDeps = [pkgs.rust pkgs.rust.dev pkgs.python3 pkgs.sed pkgs.pkg-config pkgs.protobuf pkgs.cargo-nextest];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "compile-and-discover";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
          export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target" CARGO_INCREMENTAL=0
          export OPENSSL_DIR=${pkgs.openssl} OPENSSL_LIB_DIR=${pkgs.openssl}/lib
          export OPENSSL_INCLUDE_DIR=${pkgs.openssl}/include OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0
          export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 PROTOC=${pkgs.protobuf}/bin/protoc
          mkdir -p "$CARGO_HOME" .cargo "$out"
          sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
            ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
          printf '#!${pkgs.python3}/bin/python3\n' > "$TMPDIR/rustc-wrapper"
          cat ${../../tools/bazel/tests/trace_cargo_rustc.py} >> "$TMPDIR/rustc-wrapper"
          chmod +x "$TMPDIR/rustc-wrapper"
          export RUSTC_WRAPPER="$TMPDIR/rustc-wrapper"
          export AOS_CARGO_RUSTC_TRACE="$out/compiler-arguments.jsonl"

          cargo test --release --frozen --offline --manifest-path crates/Cargo.toml \
            ${packageFlags} --features crucible-cli/test-double \
            --jobs "$NIX_BUILD_CORES" --no-run --message-format=json \
            > "$out/cargo-messages.jsonl"
          cp "$out/compiler-arguments.jsonl" "$out/compiler-compile-arguments.jsonl"

          # Discovery retains ignored cases and the ordinary Nextest filters.
          # It executes libtest listing only; this is not a passing test run.
          ulimit -S -n 4096
          cargo nextest list --cargo-profile release --frozen --offline \
            --manifest-path crates/Cargo.toml ${packageFlags} \
            --features crucible-cli/test-double --message-format json \
            > "$out/nextest-list.json"
          cat > "$out/scope.json" <<'JSON'
          ${builtins.toJSON {
            inherit packages;
            features = ["crucible-cli/test-double"];
            cargo_profile = "release";
            compilation_and_discovery_only = true;
            test_execution_qualified = false;
          }}
          JSON
        '';
      }
    ];
  }
