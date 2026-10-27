{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.campaignRfcTraceability",
  automatedTargets ? {},
  deferredTargetNames ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
  automatedTargetNames = builtins.attrNames automatedTargets;
  automatedTargetValues = builtins.attrValues automatedTargets;
  invalidTargets = builtins.filter (target: !(lib.isDerivation target)) automatedTargetValues;
in
  if invalidTargets != []
  then throw "every RFC-0020 automated gate target must evaluate to a derivation"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase4-campaign-rfc-traceability";

      buildDeps = [pkgs.coreutils];
      ATTR_PATH = attrPath;
      AUTOMATED_TARGETS = builtins.concatStringsSep "," automatedTargetNames;
      DEFERRED_AUTOMATED_TARGETS = builtins.concatStringsSep "," deferredTargetNames;

      phases = [
        {
          name = "run-campaign-rfc-traceability";
          script = ''
            set -eu

            crucible-cargo test \
              -p crucible-test-support --test campaign_gate_traceability -- --test-threads=1
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
              printf 'scope=catalog,cargo-targets,automated-evidence-contracts,nix-wiring\n'
            } > "$out/result"
          '';
        }
      ];
    }
