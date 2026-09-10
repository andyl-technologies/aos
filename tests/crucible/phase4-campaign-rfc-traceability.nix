{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.campaignRfcTraceability",
  automatedTargets ? {},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  automatedTargetNames = builtins.attrNames automatedTargets;
  automatedTargetValues = builtins.attrValues automatedTargets;
  invalidTargets = builtins.filter (target: !(lib.isDerivation target)) automatedTargetValues;
in
  if invalidTargets != []
  then throw "every RFC-0020 automated gate target must evaluate to a derivation"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-campaign-rfc-traceability";
      version = "0";
      src = crucibleSrc;

      buildDeps = [pkgs.coreutils pkgs.rust];
      ATTR_PATH = attrPath;
      AUTOMATED_TARGETS = builtins.concatStringsSep "," automatedTargetNames;

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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          '';
        }
        {
          name = "run-campaign-rfc-traceability";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            cargo test --frozen --offline --manifest-path crates/Cargo.toml \
              --target-dir "$TMPDIR/campaign-rfc-traceability-target" \
              -p crucible-harness --test campaign_gate_traceability -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            {
              printf 'PASS\n'
              printf 'check=%s\n' "$ATTR_PATH"
              printf 'automated_targets=%s\n' "$AUTOMATED_TARGETS"
              printf 'scope=catalog,cargo-targets,manual-artifact-contracts,nix-wiring\n'
            } > "$out/result"
          '';
        }
      ];
    }
