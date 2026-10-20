##! Exercises shared Cargo target repair without changing vendor files or freshness.
{pkgs}: let
  phaseTemplates = import ../../stdenv/phases.nix;
  vendor = pkgs.runCommand "cargo-cache-permissions-vendor" {} ''
    mkdir -p "$out"
  '';
  configure = builtins.head (builtins.filter (phase: phase.name == "configure")
    (phaseTemplates.cargoPhases {
      cargoDeps = vendor;
      cargoSourceId = "cache-permissions-fixture";
      cargoCacheLock = pkgs.util-linux;
      doCheck = false;
    }));
in
  pkgs.mkDerivation {
    pname = "cargo-cache-permissions-check";
    version = "1";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          export CARGO_TARGET_DIR="$TMPDIR/cache/target"
          mkdir -p "$CARGO_TARGET_DIR/dir with spaces" \
            "$CARGO_TARGET_DIR/release/incremental/fixture" "$TMPDIR/source"
          cd "$TMPDIR/source"

          readonlyFile="$CARGO_TARGET_DIR/dir with spaces/bindgen.rs"
          executableFile="$CARGO_TARGET_DIR/build-script"
          writableFile="$CARGO_TARGET_DIR/already-writable"
          vendorFile="$TMPDIR/vendor.rs"
          incrementalLock="$CARGO_TARGET_DIR/release/incremental/fixture/session.lock"
          printf '%s\n' 'generated binding' > "$readonlyFile"
          printf '%s\n' 'executable payload' > "$executableFile"
          printf '%s\n' 'ordinary output' > "$writableFile"
          printf '%s\n' 'immutable vendor source' > "$vendorFile"
          touch -t 200001010000 "$readonlyFile" "$executableFile"
          chmod 444 "$readonlyFile" "$vendorFile"
          chmod 555 "$executableFile"
          touch "$incrementalLock"
          chmod 000 "$incrementalLock"
          touch "$incrementalLock.aos-writable.interrupted"
          chmod 000 "$incrementalLock.aos-writable.interrupted"
          ln -s "$vendorFile" "$CARGO_TARGET_DIR/vendor-link"

          readonlyInode=$(stat -c %i "$readonlyFile")
          readonlyMtime=$(stat -c %Y "$readonlyFile")
          executableMtime=$(stat -c %Y "$executableFile")
          writableInode=$(stat -c %i "$writableFile")
          ${configure.script}

          test "$(stat -c %a "$readonlyFile")" = 666
          test "$(stat -c %i "$readonlyFile")" != "$readonlyInode"
          test "$(stat -c %Y "$readonlyFile")" = "$readonlyMtime"
          grep -qx 'generated binding' "$readonlyFile"
          test "$(stat -c %a "$executableFile")" = 777
          test "$(stat -c %Y "$executableFile")" = "$executableMtime"
          grep -qx 'executable payload' "$executableFile"
          test "$(stat -c %i "$writableFile")" = "$writableInode"
          test "$(stat -c %a "$vendorFile")" = 444
          test "$(readlink "$CARGO_TARGET_DIR/vendor-link")" = "$vendorFile"
          test "$(stat -c %a "$incrementalLock")" = 666
          test -r "$incrementalLock" && test -w "$incrementalLock"
          test ! -s "$incrementalLock"

          repairedInode=$(stat -c %i "$readonlyFile")
          ${configure.script}
          test "$(stat -c %i "$readonlyFile")" = "$repairedInode"
          test -z "$(find "$CARGO_TARGET_DIR" -name '*.aos-writable.*' -print)"

          # Simulate a CMake install changing modes after configuration. Both
          # successful and failed builders must leave directories reusable.
          generatedDirectory="$CARGO_TARGET_DIR/release/build/fixture/out/generated"
          mkdir -p "$generatedDirectory"
          chmod 500 "$generatedDirectory"
          (trap finishSharedCargoCache EXIT)
          test "$(stat -c %a "$generatedDirectory")" = 777

          chmod 500 "$generatedDirectory"
          if (trap finishSharedCargoCache EXIT; exit 7); then
            echo 'cache cleanup hid the builder failure' >&2
            exit 1
          else
            test "$?" = 7
          fi
          test "$(stat -c %a "$generatedDirectory")" = 777

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
