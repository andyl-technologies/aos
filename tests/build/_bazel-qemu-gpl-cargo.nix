##! Retains an independent offline Cargo baseline until GPL qualification completes.
{
  pkgs,
  retainExecutionTrace ? false,
}: let
  root = ../..;
  traceCommand = pkgs.lib.optionalString retainExecutionTrace ''
    ${pkgs.strace}/bin/strace -qq -f -s 16777216 \
      -e trace=execve,execveat -e signal=none \
      -o "$out/compiler-exec.log" \
  '';
in
  pkgs.mkDerivation {
    pname = "aos-bazel-qemu-gpl-production-cargo" + pkgs.lib.optionalString retainExecutionTrace "-exec-trace";
    version = "1";
    src = import (root + "/pkgs/tools/crucible/_cargo-source.nix") {inherit (pkgs) lib;};
    buildDeps = [pkgs.rust pkgs.python3 pkgs.sed] ++ pkgs.lib.optional retainExecutionTrace pkgs.strace;
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
          export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target" CARGO_INCREMENTAL=0
          mkdir -p "$CARGO_HOME" .cargo "$out/artifacts"
          sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
            ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
          set -a
          . ${pkgs.aosBazelQemuPluginAbi}/plugin.env
          set +a
          printf '#!${pkgs.python3}/bin/python3\n' > "$TMPDIR/rustc-wrapper"
          cat ${root + "/tools/bazel/tests/trace_cargo_rustc.py"} >> "$TMPDIR/rustc-wrapper"
          chmod +x "$TMPDIR/rustc-wrapper"
          export RUSTC_WRAPPER="$TMPDIR/rustc-wrapper" AOS_CARGO_RUSTC_TRACE="$out/compiler-arguments.jsonl"
          ${traceCommand}cargo build --release --frozen --offline --manifest-path crates/Cargo.toml \
            -p crucible-qemu-plugin -p crucible-qemu-debug-gateway --jobs "$NIX_BUILD_CORES" \
            --message-format=json > "$out/cargo-messages.jsonl"
          cp "$CARGO_TARGET_DIR/release/libcrucible_qemu_plugin.so" \
            "$CARGO_TARGET_DIR/release/crucible-debug-gateway" "$out/artifacts/"
        '';
      }
    ];
  }
