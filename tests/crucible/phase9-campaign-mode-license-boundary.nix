{
  pkgs,
  lib,
  mode,
  system,
}: let
  toplevel = system.config.system.build.toplevel;
  gate = import ./phase1-license-boundary.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase1.gates.licenseBoundary";
    campaignComposition = {inherit mode system;};
  };
in
  assert builtins.elem mode ["disabled" "enabled"];
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-mode-license-boundary-${mode}";
      version = "0";
      src = null;
      buildDeps = [gate pkgs.coreutils pkgs.grep pkgs.sed];
      phases = [
        {
          name = "authenticate-mode-specific-license-gate";
          script = ''
            set -eu
            grep -Fxq PASS ${gate}/result
            grep -Fxq 'gate=gate:license-boundary' ${gate}/result
            grep -Fxq 'campaign_mode=${mode}' ${gate}/result
            grep -Fxq 'campaign_closure_authenticated=true' ${gate}/result
            test -s ${gate}/campaign-runtime.env
            test -s ${gate}/campaign-system-closure

            configuration_identity=$(sed -n 's/^identity=//p' ${gate}/campaign-runtime.env)
            test -n "$configuration_identity"
            test "$(printf '%s\n' "$configuration_identity" | wc -l | tr -d ' ')" -eq 1

            mkdir -p "$out"
            cp ${gate}/result "$out/raw-result"
            {
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_BEGIN'
              cat ${gate}/result
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_END'
              printf '%s\n' '--- campaign-runtime.env ---'
              cat ${gate}/campaign-runtime.env
              printf '%s\n' '--- campaign-system-closure ---'
              cat ${gate}/campaign-system-closure
            } > "$out/transcript"
            cat > "$out/result" <<RESULT
            PASS
            gate=gate:license-boundary
            authoritative_attr=checks.crucible.phase1.gates.licenseBoundary
            execution_family=static-closure
            campaign_mode=${mode}
            campaign_configuration_identity=$configuration_identity
            campaign_toplevel=${toplevel}
            executor_derivation=${gate}
            exact_system_closure_authenticated=true
            retained_transcript=true
            RESULT
          '';
        }
      ];
    }
