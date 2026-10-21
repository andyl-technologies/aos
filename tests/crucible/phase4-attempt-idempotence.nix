{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.attemptIdempotence",
  taskIds ? ["T-CAM-4.2" "T-CAM-4.9"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase4-attempt-idempotence";

    buildDeps = [pkgs.coreutils] ++ dependencies;

    phases = [
      {
        name = "run-attempt-idempotence";
        script = ''
          set -eu

          crucible-cargo test \
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
