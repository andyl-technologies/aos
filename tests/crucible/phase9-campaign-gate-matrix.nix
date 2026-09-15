{
  pkgs,
  lib,
  campaignModeAuthorities,
  modeGateAdapters,
  attrPath ? "checks.crucible.phase9.gates.campaignGateMatrix",
  taskIds ? ["T-CAM-9.1"],
}: let
  inventoryPath = ./campaign-gate-matrix-inventory.toml;
  inventory = builtins.fromTOML (builtins.readFile inventoryPath);
  authorities = inventory.authorities;
  expectedGateNames = map (authority: authority.gate) authorities;
  actualGateNames = builtins.attrNames modeGateAdapters;
  missingAdapters = builtins.filter (gate: !(builtins.hasAttr gate modeGateAdapters)) expectedGateNames;
  unknownAdapters = builtins.filter (gate: !(builtins.elem gate expectedGateNames)) actualGateNames;
  expectedModes = ["disabled" "enabled"];
  actualModes = builtins.attrNames campaignModeAuthorities;
  missingModes = builtins.filter (mode: !(builtins.hasAttr mode campaignModeAuthorities)) expectedModes;
  unknownModes = builtins.filter (mode: !(builtins.elem mode expectedModes)) actualModes;
  presentGateNames = builtins.filter (gate: builtins.hasAttr gate modeGateAdapters) expectedGateNames;
  adapterDerivations =
    lib.concatMap (
      gate: let
        adapter = modeGateAdapters.${gate};
      in [
        adapter.disabled
        adapter.enabled
      ]
    )
    presentGateNames;
  adapterPaths = map toString adapterDerivations;
  duplicateAdapterPaths =
    builtins.length adapterPaths
    != builtins.length (lib.unique adapterPaths);
  failures =
    map (gate: "${gate}: missing authoritative mode adapter") missingAdapters
    ++ map (gate: "${gate}: unknown mode adapter") unknownAdapters
    ++ map (mode: "${mode}: missing campaign mode authority") missingModes
    ++ map (mode: "${mode}: unknown campaign mode authority") unknownModes
    ++ lib.optional (
      missingModes
      == []
      && campaignModeAuthorities.disabled.configurationIdentity
      == campaignModeAuthorities.enabled.configurationIdentity
    ) "campaign-disabled and campaign-enabled configuration identities are equal"
    ++ lib.optional (
      missingModes
      == []
      && toString campaignModeAuthorities.disabled.toplevel
      == toString campaignModeAuthorities.enabled.toplevel
    ) "campaign-disabled and campaign-enabled system toplevels are equal"
    ++ lib.optional duplicateAdapterPaths "two gate/mode rows alias one adapter derivation";
  authenticateRows =
    lib.concatMapStringsSep "\n" (authority: let
      gate = authority.gate;
      safeGate = lib.removePrefix "gate:" gate;
      adapter = modeGateAdapters.${gate};
    in ''
      authenticate_adapter \
        ${lib.escapeShellArg gate} \
        ${lib.escapeShellArg authority.attr_path} \
        ${lib.escapeShellArg authority.execution_family} \
        disabled \
        ${lib.escapeShellArg campaignModeAuthorities.disabled.configurationIdentity} \
        ${lib.escapeShellArg (toString campaignModeAuthorities.disabled.toplevel)} \
        ${lib.escapeShellArg (toString adapter.disabled)} \
        ${lib.escapeShellArg safeGate}
      authenticate_adapter \
        ${lib.escapeShellArg gate} \
        ${lib.escapeShellArg authority.attr_path} \
        ${lib.escapeShellArg authority.execution_family} \
        enabled \
        ${lib.escapeShellArg campaignModeAuthorities.enabled.configurationIdentity} \
        ${lib.escapeShellArg (toString campaignModeAuthorities.enabled.toplevel)} \
        ${lib.escapeShellArg (toString adapter.enabled)} \
        ${lib.escapeShellArg safeGate}
      cmp \
        "$out/disabled/${safeGate}/semantic-result" \
        "$out/enabled/${safeGate}/semantic-result"
    '')
    authorities;
in
  if failures != []
  then throw "crucible phase9 campaign gate matrix is incomplete:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-gate-matrix";
      version = "0";
      src = null;
      buildDeps = adapterDerivations ++ [pkgs.coreutils pkgs.grep pkgs.sed];
      phases = [
        {
          name = "authenticate-mode-gate-matrix";
          script = ''
            set -eu
            . ${./_phase9-campaign-gate-matrix-authenticate.sh}
            mkdir -p "$out/disabled" "$out/enabled"
            : > "$out/execution-manifest.tsv"

            field() {
              name="$1"
              result="$2"
              value=$(sed -n "s/^$name=//p" "$result")
              test -n "$value"
              test "$(printf '%s\n' "$value" | wc -l | tr -d ' ')" -eq 1
              printf '%s' "$value"
            }

            require_exact_line() {
              line="$1"
              result="$2"
              test "$(grep -Fxc "$line" "$result" || true)" -eq 1
            }

            authenticate_adapter() {
              gate="$1"
              authority="$2"
              family="$3"
              mode="$4"
              expected_configuration_identity="$5"
              expected_toplevel="$6"
              adapter="$7"
              safe_gate="$8"
              destination="$out/$mode/$safe_gate"

              test -f "$adapter/result"
              test -f "$adapter/raw-result"
              test -f "$adapter/transcript"
              require_exact_line PASS "$adapter/result"
              require_exact_line "gate=$gate" "$adapter/result"
              require_exact_line "authoritative_attr=$authority" "$adapter/result"
              require_exact_line "execution_family=$family" "$adapter/result"
              require_exact_line "campaign_mode=$mode" "$adapter/result"

              configuration_identity=$(field campaign_configuration_identity "$adapter/result")
              toplevel=$(field campaign_toplevel "$adapter/result")
              executor=$(field executor_derivation "$adapter/result")
              test "$configuration_identity" = "$expected_configuration_identity"
              test "$toplevel" = "$expected_toplevel"
              test -e "$toplevel"
              test -e "$executor"

              test "$(grep -Fxc 'CAMPAIGN_GATE_RESULT_BEGIN' "$adapter/transcript")" -eq 1
              test "$(grep -Fxc 'CAMPAIGN_GATE_RESULT_END' "$adapter/transcript")" -eq 1
              awk '
                /^CAMPAIGN_GATE_RESULT_BEGIN$/ {
                  if (state != 0) exit 1
                  state = 1
                  next
                }
                /^CAMPAIGN_GATE_RESULT_END$/ {
                  if (state != 1) exit 1
                  state = 2
                  next
                }
                state == 1 { print }
                END { if (state != 2) exit 1 }
              ' "$adapter/transcript" > "$TMPDIR/$mode-$safe_gate.raw-result"
              cmp "$TMPDIR/$mode-$safe_gate.raw-result" "$adapter/raw-result"

              authenticate_campaign_matrix_raw_result \
                "$adapter/raw-result" \
                "$gate" \
                "$mode" \
                "$expected_configuration_identity" \
                "$expected_toplevel" \
                "$executor"

              mkdir -p "$destination"
              cp "$adapter/result" "$destination/result"
              cp "$adapter/raw-result" "$destination/raw-result"
              cp "$adapter/transcript" "$destination/transcript"
              grep -Ev \
                '^(campaign_mode|campaign_configuration_identity|campaign_runtime_identity|campaign_toplevel|executor_derivation)=' \
                "$destination/raw-result" > "$TMPDIR/$mode-$safe_gate.bound-result"
              normalize_campaign_matrix_semantic_result \
                "$gate" \
                "$TMPDIR/$mode-$safe_gate.bound-result" \
                "$destination/semantic-result"
              test -s "$destination/semantic-result"
              result_sha256=$(sha256sum "$destination/result" | cut -d ' ' -f 1)
              semantic_sha256=$(sha256sum "$destination/semantic-result" | cut -d ' ' -f 1)
              transcript_sha256=$(sha256sum "$destination/transcript" | cut -d ' ' -f 1)
              printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$gate" "$mode" "$authority" "$family" "$configuration_identity" \
                "$toplevel" "$executor" "$result_sha256" "$semantic_sha256" \
                "$transcript_sha256" >> "$out/execution-manifest.tsv"
            }

            ${authenticateRows}

            test "$(wc -l < "$out/execution-manifest.tsv" | tr -d ' ')" \
              -eq ${toString (2 * builtins.length authorities)}
            test "$(cut -f1,2 "$out/execution-manifest.tsv" | sort -u | wc -l | tr -d ' ')" \
              -eq ${toString (2 * builtins.length authorities)}
            sha256sum "$out/execution-manifest.tsv" > "$out/execution-manifest.sha256"
            cp ${inventoryPath} "$out/campaign-gate-matrix-inventory.toml"

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:campaign-gate-matrix
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            inventory_sha256=${builtins.hashFile "sha256" inventoryPath}
            inventory_gate_count=${toString (builtins.length authorities)}
            mode_execution_count=${toString (2 * builtins.length authorities)}
            authoritative_aggregate_adapters=true
            retained_mode_results=true
            semantic_result_sets_identical=true
            RESULT
          '';
        }
      ];
    }
