{
  pkgs,
  lib,
  mode,
  system,
  gatePath,
  gateName,
  authoritativeAttr,
  gateArgs ? {},
}: let
  gateFunction = import gatePath;
  suppliedArgs =
    {
      inherit pkgs lib;
      attrPath = authoritativeAttr;
      campaignComposition = {inherit mode system;};
    }
    // gateArgs;
  gate = gateFunction (
    lib.filterAttrs (name: _: builtins.hasAttr name (builtins.functionArgs gateFunction)) suppliedArgs
  );
  toplevel = system.config.system.build.toplevel;
  safeGate = lib.removePrefix "gate:" gateName;
in
  assert builtins.elem mode ["disabled" "enabled"];
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-mode-${safeGate}-${mode}";
      version = "0";
      src = null;
      buildDeps = [gate pkgs.coreutils pkgs.grep pkgs.sed];
      phases = [
        {
          name = "authenticate-mode-specific-static-gate";
          script = ''
            set -eu
            test -s ${gate}/result
            grep -Fxq PASS ${gate}/result
            grep -Fxq 'gate=${gateName}' ${gate}/result
            grep -Fxq 'campaign_mode=${mode}' ${gate}/result
            grep -Fxq 'campaign_closure_authenticated=true' ${gate}/result
            test -s ${gate}/campaign-system-closure

            configuration_identity=$(sed -n \
              's/^campaign_configuration_identity=//p' ${gate}/result)
            test -n "$configuration_identity"
            test "$(printf '%s\n' "$configuration_identity" | wc -l | tr -d ' ')" -eq 1

            mkdir -p "$out"
            cp ${gate}/result "$out/raw-result"
            {
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_BEGIN'
              cat ${gate}/result
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_END'
              printf '%s\n' '--- campaign-system-closure ---'
              cat ${gate}/campaign-system-closure
            } > "$out/transcript"
            cat > "$out/result" <<RESULT
            PASS
            gate=${gateName}
            authoritative_attr=${authoritativeAttr}
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
