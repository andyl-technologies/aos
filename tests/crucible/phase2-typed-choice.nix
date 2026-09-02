{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.typedChoice",
  taskIds ? ["T-CAM-2.1" "T-CAM-2.2" "T-CAM-2.4" "T-CAM-2.5" "T-CAM-2.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-typed-choice";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.rust];
    ATTR_PATH = attrPath;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-typed-choice";
        script = ''
          set -eu
          : "$DEPENDENCY_PATHS"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-campaign --lib -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-campaign --test gate_typed_choice -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-protocol --lib selectable -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-guest --lib selectable -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:typed-choice\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'scope=typed-domain,selection-replay,guest-selectable-codec\n'
          } > "$out/result"
        '';
      }
    ];
  }
