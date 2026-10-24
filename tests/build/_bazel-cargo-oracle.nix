##! Temporary offline Cargo execution evidence for Bazel family comparisons.
{
  pkgs,
  pname,
  packages,
  libOnly ? false,
  nativeLibraries ? [],
  nativeTools ? [],
  cargoFlags ? [],
  cargoSource ? import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;},
  cargoSetup ? "",
  captureCompilerArguments ? false,
}: let
  packageFlags = pkgs.lib.escapeShellArgs (
    pkgs.lib.concatMap (name: ["-p" name]) packages
    ++ pkgs.lib.optionals libOnly ["--lib"] ++ cargoFlags
  );
in
  pkgs.mkDerivation {
    inherit pname;
    version = "1";
    src = cargoSource;
    buildDeps = [pkgs.rust pkgs.python3 pkgs.sed] ++ nativeTools;
    runtimeDeps = nativeLibraries;
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "compare";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
          export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target"
          mkdir -p "$CARGO_HOME" .cargo "$out"
          sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
            ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
          ${pkgs.lib.optionalString captureCompilerArguments ''
            printf '#!${pkgs.python3}/bin/python3\n' > "$TMPDIR/rustc-wrapper"
            cat ${../../tools/bazel/tests/trace_cargo_rustc.py} >> "$TMPDIR/rustc-wrapper"
            chmod +x "$TMPDIR/rustc-wrapper"
            export RUSTC_WRAPPER="$TMPDIR/rustc-wrapper"
            export AOS_CARGO_RUSTC_TRACE="$out/compiler-arguments.jsonl"
          ''}${cargoSetup}cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            ${packageFlags} \
            --jobs "$NIX_BUILD_CORES" --no-run --message-format=json > "$out/cargo-messages.jsonl" || {
            ${pkgs.python3}/bin/python3 - "$out/cargo-messages.jsonl" <<'PY'
          import json
          from pathlib import Path
          import sys

          for line in Path(sys.argv[1]).read_text().splitlines():
              event = json.loads(line)
              if event.get("reason") == "compiler-message" and event["message"]["level"] == "error":
                  print(event["message"].get("rendered") or event["message"]["message"], file=sys.stderr)
          PY
            exit 1
          }
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            ${packageFlags} \
            --jobs "$NIX_BUILD_CORES" > "$out/cargo-tests.log" 2>&1 || {
            tail -n 100 "$out/cargo-tests.log"
            exit 1
          }
          # Keep discovered binaries so parity checks can evolve independently
          # of the Cargo compilation oracle during the migration.
          ${pkgs.python3}/bin/python3 - "$out" <<'PY'
          import json
          from pathlib import Path
          import shutil
          import sys

          output = Path(sys.argv[1])
          binaries = output / "test-binaries"
          binaries.mkdir()
          messages = output / "cargo-messages.jsonl"
          events = [json.loads(line) for line in messages.read_text().splitlines()]
          for event in events:
              executable = event.get("executable")
              if event.get("reason") == "compiler-artifact" and executable:
                  target = binaries / Path(executable).name
                  shutil.copy2(executable, target)
                  event["executable"] = str(target)
          messages.write_text("".join(json.dumps(event) + "\n" for event in events))
          PY
        '';
      }
    ];
  }
