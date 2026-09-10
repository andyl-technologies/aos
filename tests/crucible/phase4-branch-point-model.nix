{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.branchPointModel",
  taskIds ? ["T-CAM-4.1" "T-CAM-4.2" "T-CAM-4.3" "T-CAM-4.4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase4-branch-point-model";
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
        name = "run-branch-point-model";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/branch-point-model-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-campaign \
            --test gate_branch_point_model \
            -- --test-threads=1

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:branch-point-model
          scope=parent-scoped-identity,finite-generated-convergence,lazy-cursors,semantic-deduplication,immutable-execution-basis,retained-causes,observation-credit,cold-restart,statistical-intervention-exclusion
          RESULT
        '';
      }
    ];
  }
