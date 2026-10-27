##! Runs the original gateway lifecycle assertions with a separate Apache client.
{
  pkgs,
  release ? false,
}: let
  root = ../..;
  releaseFlag = pkgs.lib.optionalString release " --release";
  profileDirectory =
    if release
    then "release"
    else "debug";
in
  pkgs.mkDerivation {
    pname = "aos-bazel-qemu-process-cargo" + pkgs.lib.optionalString release "-release";
    version = "1";
    src = import (root + "/pkgs/tools/crucible/_cargo-source.nix") {inherit (pkgs) lib;};
    buildDeps = [pkgs.rust pkgs.python3 pkgs.sed pkgs.pkg-config];
    runtimeDeps = [pkgs.sqlite pkgs.zstdStaticMultithread];
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "qualify";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
          export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target-host" CARGO_INCREMENTAL=0
          export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
          mkdir -p "$CARGO_HOME" .cargo "$out/host/artifacts" "$out/gpl/test-binaries"
          sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
            ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
          printf '#!${pkgs.python3}/bin/python3\n' > "$TMPDIR/rustc-wrapper"
          cat ${root + "/tools/bazel/tests/trace_cargo_rustc.py"} >> "$TMPDIR/rustc-wrapper"
          chmod +x "$TMPDIR/rustc-wrapper"
          export RUSTC_WRAPPER="$TMPDIR/rustc-wrapper"

          export AOS_CARGO_RUSTC_TRACE="$out/host/compiler-arguments.jsonl"
          cargo build${releaseFlag} --frozen --offline --manifest-path crates/Cargo.toml \
            -p crucible-control-server --bin crucible-qemu-test-oracle --features qemu-test-oracle \
            --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/host/cargo-messages.jsonl"
          cp "$CARGO_TARGET_DIR/${profileDirectory}/crucible-qemu-test-oracle" "$out/host/artifacts/"
          export CRUCIBLE_QEMU_TEST_ORACLE="$out/host/artifacts/crucible-qemu-test-oracle"

          # Separate outputs retain every compiler invocation in both graphs;
          # a reused host artifact would hide a GPL-side feature selection.
          export CARGO_TARGET_DIR="$TMPDIR/target-gpl"
          export AOS_CARGO_RUSTC_TRACE="$out/gpl/compiler-arguments.jsonl"
          cargo test${releaseFlag} --frozen --offline --manifest-path crates/Cargo.toml \
            -p crucible-qemu-debug-gateway --lib --bins --test process_lifecycle \
            --jobs "$NIX_BUILD_CORES" --no-run --message-format=json > "$out/gpl/cargo-messages.jsonl"
          cargo test${releaseFlag} --frozen --offline --manifest-path crates/Cargo.toml \
            -p crucible-qemu-debug-gateway --lib --bins --test process_lifecycle \
            --jobs "$NIX_BUILD_CORES" -- --nocapture > "$out/gpl/cargo-tests.log" 2>&1 || {
            tail -n 70 "$out/gpl/cargo-tests.log"
            exit 1
          }
          ${pkgs.python3}/bin/python3 - "$out" <<'PY'
          import json
          from pathlib import Path
          import shutil
          import sys

          output = Path(sys.argv[1])
          for family in ["host", "gpl"]:
              messages = output / family / "cargo-messages.jsonl"
              events = [json.loads(line) for line in messages.read_text().splitlines()]
              destination = output / family / "test-binaries"
              destination.mkdir(exist_ok=True)
              for event in events:
                  executable = event.get("executable")
                  if event.get("reason") == "compiler-artifact" and executable:
                      retained = destination / Path(executable).name
                      shutil.copy2(executable, retained)
                      event["executable"] = str(retained)
              messages.write_text("".join(json.dumps(event) + "\n" for event in events))
          PY
        '';
      }
    ];
  }
