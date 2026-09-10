{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.campaignMutationScaling",
  taskIds ? ["T-CAM-4.10"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase4-campaign-mutation-scaling";
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
        name = "run-campaign-mutation-scaling";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/campaign-mutation-scaling-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-campaign \
            --features test-support \
            --test gate_campaign_mutation_scaling \
            -- --test-threads=1

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-mutation-scaling
          mutations=10000
          scope=bounded-hot-validation,complete-cold-validation,failure-atomic-checkpoints,deep-closure-authentication,exact-result-locators
          RESULT
        '';
      }
    ];
  }
