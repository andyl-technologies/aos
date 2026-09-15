{
  pkgs,
  lib,
  campaignComposition ? null,
  attrPath,
  taskIds ? [],
  openTaskIds ? [],
  dependencies ? [],
  gate,
  executionFamily,
  name,
  authority,
  requiredEvidence,
  semanticEvidence,
}: let
  selected = campaignComposition != null;
  mode =
    if selected
    then campaignComposition.mode
    else null;
  system =
    if selected
    then campaignComposition.system
    else null;
  configurationIdentity =
    if selected
    then system.config.aos.services.crucibleCampaign._runtimeIdentity
    else null;
  toplevel =
    if selected
    then system.config.system.build.toplevel
    else null;
  authorityResult =
    if selected
    then "${authority}/raw-result"
    else "${authority}/result";
  semanticResult = builtins.concatStringsSep "\n" ([
      "PASS"
      "check=${attrPath}"
      "gate=${gate}"
      "tasks=${builtins.concatStringsSep "," taskIds}"
      "open_tasks=${builtins.concatStringsSep "," openTaskIds}"
      "status=complete"
    ]
    ++ semanticEvidence);
in
  pkgs.mkDerivation {
    pname = "crucible-${name}";
    version = "0";
    src = null;
    buildDeps = [authority pkgs.coreutils pkgs.grep] ++ dependencies;
    phases = [
      {
        name = "authenticate-production-evidence";
        script = ''
          set -eu
          source_result=${lib.escapeShellArg authorityResult}

          require_exact_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$source_result")" -eq 1
          }

          require_exact_line PASS
          ${lib.optionalString selected ''
            require_exact_line 'campaign_mode=${mode}'
            require_exact_line 'campaign_configuration_identity=${configurationIdentity}'
            require_exact_line 'campaign_toplevel=${toplevel}'
            test "$(grep -Ec '^executor_derivation=/nix/store/[0-9a-z]+-.+$' "$source_result")" -eq 1
            test "$(grep -c '^campaign_mode=' "$source_result")" -eq 1
            test "$(grep -c '^campaign_configuration_identity=' "$source_result")" -eq 1
            test "$(grep -c '^campaign_toplevel=' "$source_result")" -eq 1
            test "$(grep -c '^executor_derivation=' "$source_result")" -eq 1
            source_executor_line="$(grep '^executor_derivation=' "$source_result")"
            source_executor="''${source_executor_line#executor_derivation=}"
            test -e "$source_executor"
          ''}
          ${lib.concatMapStringsSep "\n" (line: "require_exact_line ${lib.escapeShellArg line}") requiredEvidence}

          mkdir -p "$out"
          cp "$source_result" "$out/authority.result"
          cat > "$out/result" <<RESULT
          ${semanticResult}
          ${lib.optionalString selected ''
            authoritative_attr=${attrPath}
            execution_family=${executionFamily}
            campaign_mode=${mode}
            campaign_configuration_identity=${configurationIdentity}
            campaign_toplevel=${toplevel}
            executor_derivation=$out
            retained=true
          ''}
          RESULT

          ${lib.optionalString selected ''
            test -f ${authority}/transcript
            cp ${authority}/transcript "$out/authority.transcript"
            cp "$out/result" "$out/raw-result"
            {
              printf '%s\n' CAMPAIGN_GATE_RESULT_BEGIN
              cat "$out/raw-result"
              printf '%s\n' CAMPAIGN_GATE_RESULT_END
            } > "$out/transcript"
          ''}
        '';
      }
    ];
  }
