{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.attemptIdempotence",
  taskIds ? ["T-CAM-4.2" "T-CAM-4.9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase4-attempt-idempotence";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.rust] ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-attempt-idempotence";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/attempt-idempotence-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-campaign \
            --test gate_attempt_idempotence \
            -- --test-threads=1

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:attempt-idempotence
          matrix=admission-replay,assignment-replay,running-retry,assignment-conflict,pre-publication-restart,ref-cas-retry,post-publication-replay,equal-completion,conflicting-completion,exact-credit
          RESULT
        '';
      }
    ];
  }
