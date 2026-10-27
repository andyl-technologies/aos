##! Repeats the ordinary controller's three separate pre-install compilations.
{pkgs}: let
  contexts = {
    cli = {
      package = "crucible-cli";
      arguments = ["--bin" "crucible"];
      executable = "crucible";
    };
    debugger = {
      package = "crucible-engine";
      arguments = ["--example" "crucible-debugger-live-fixture"];
      executable = "examples/crucible-debugger-live-fixture";
    };
    scenario = {
      package = "crucible-daemon";
      arguments = ["--example" "crucible-e2e-determinism-scenario"];
      executable = "examples/crucible-e2e-determinism-scenario";
    };
  };
  compile = name: context: ''
    export CARGO_TARGET_DIR="$TMPDIR/target-${name}"
    export AOS_CARGO_RUSTC_TRACE="$out/${name}/compiler-arguments.jsonl"
    mkdir -p "$out/${name}/artifacts"
    cargo build --release --frozen --offline --manifest-path crates/Cargo.toml \
      -p ${context.package} ${pkgs.lib.escapeShellArgs context.arguments} \
      --jobs "$NIX_BUILD_CORES" --message-format=json \
      > "$out/${name}/cargo-messages.jsonl"
    cp "$CARGO_TARGET_DIR/release/${context.executable}" "$out/${name}/artifacts/"
  '';
in
  pkgs.mkDerivation {
    pname = "aos-bazel-crucible-controller-production-cargo";
    version = "1";
    src = import ../../pkgs/tools/crucible/_source.nix {inherit (pkgs) lib;};
    buildDeps = [pkgs.rust pkgs.python3 pkgs.sed pkgs.pkg-config pkgs.protobuf];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "compile";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
          export CARGO_HOME="$TMPDIR/cargo" CARGO_INCREMENTAL=0
          export OPENSSL_DIR=${pkgs.openssl} OPENSSL_LIB_DIR=${pkgs.openssl}/lib
          export OPENSSL_INCLUDE_DIR=${pkgs.openssl}/include OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0
          export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 PROTOC=${pkgs.protobuf}/bin/protoc
          mkdir -p "$CARGO_HOME" .cargo
          sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
            ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
          printf '#!${pkgs.python3}/bin/python3\n' > "$TMPDIR/rustc-wrapper"
          cat ${../../tools/bazel/tests/trace_cargo_rustc.py} >> "$TMPDIR/rustc-wrapper"
          chmod +x "$TMPDIR/rustc-wrapper"
          export RUSTC_WRAPPER="$TMPDIR/rustc-wrapper"

          ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList compile contexts)}
        '';
      }
    ];
  }
