{
  pkgs,
  lib,
  testing,
  mode,
  system,
  gateName,
  authoritativeAttr,
  authoritativeResultIdentity ? "gate=${gateName}",
  executionFamily,
  name,
  runtimeInputs,
  runtimeClosures ? [],
  runtimeEnvironment ? {},
  runtimeScript,
  timeout ? 1800,
  memoryMiB ? 4096,
  varSizeMiB ? 4096,
}: let
  toplevel = system.config.system.build.toplevel;
  expectedConfigurationIdentity = system.config.aos.services.crucibleCampaign._runtimeIdentity;
  runtimeTools = [pkgs.bash pkgs.coreutils pkgs.tar];
  runtimePath = lib.makeBinPath (runtimeInputs ++ runtimeTools);
  environmentExports = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      variable: value: "export ${variable}=${lib.escapeShellArg (toString value)}"
    )
    runtimeEnvironment
  );
  fleet = testing.mkFleetTest {
    name = "crucible-campaign-mode-${name}-${mode}";
    inherit timeout;
    machines.primary = {
      inherit system memoryMiB varSizeMiB;
      extraClosures = runtimeInputs ++ runtimeClosures ++ runtimeTools ++ [pkgs.crucible];
    };
    testScript = ''
      import base64
      import shlex

      mode = ${builtins.toJSON mode}
      expected_identity = ${builtins.toJSON expectedConfigurationIdentity}
      expected_toplevel = ${builtins.toJSON (toString toplevel)}
      primary.wait_for_unit("multi-user.target", timeout=180)
      actual_toplevel = primary.succeed("readlink -f /run/current-system").strip()
      assert actual_toplevel == expected_toplevel, (actual_toplevel, expected_toplevel)

      runtime = primary.succeed("cat /etc/crucible/campaign-runtime.env")
      assert f"enabled={str(mode == 'enabled').lower()}\n" in runtime
      identity = next(
          line.removeprefix("identity=")
          for line in runtime.splitlines()
          if line.startswith("identity=")
      )
      assert identity == expected_identity, (identity, expected_identity)

      if mode == "enabled":
          primary.wait_for_unit("crucible-campaign.service", timeout=180)
          primary.wait_until_succeeds(
              "test -S /run/crucible-campaign/service.sock", timeout=60
          )
          primary.succeed(
              ${builtins.toJSON "${pkgs.crucible}/bin/crucible --format json campaign --socket /run/crucible-campaign/service.sock --principal operator list"}
          )
      else:
          primary.fail("systemctl is-active crucible-campaign.service")
          primary.fail("test -e /run/crucible-campaign/service.sock")
          primary.fail("command -v crucible")

      command = (
          "export out=/tmp/campaign-mode-gate-output; "
          "export TMPDIR=/tmp/campaign-mode-gate-work; "
          + "export PATH=" + shlex.quote(${builtins.toJSON runtimePath}) + "; "
          + "rm -rf \"$out\" \"$TMPDIR\"; mkdir -p \"$out\" \"$TMPDIR\"; "
          + ${builtins.toJSON environmentExports}
          + "; ${pkgs.bash}/bin/bash -c "
          + shlex.quote(${builtins.toJSON runtimeScript})
      )
      transcript = primary.succeed(command, timeout=${toString timeout})
      authoritative_result = primary.succeed(
          "cat /tmp/campaign-mode-gate-output/result"
      )
      result_lines = authoritative_result.splitlines()
      assert result_lines.count("PASS") == 1, authoritative_result
      assert result_lines.count(${builtins.toJSON authoritativeResultIdentity}) == 1, authoritative_result
      forbidden_prefixes = (
          "campaign_mode=",
          "campaign_configuration_identity=",
          "campaign_toplevel=",
          "executor_derivation=",
      )
      assert not any(
          line.startswith(forbidden_prefixes) for line in result_lines
      ), authoritative_result

      mode_result = "\n".join([
          *result_lines,
          f"campaign_mode={mode}",
          f"campaign_configuration_identity={identity}",
          f"campaign_toplevel={actual_toplevel}",
      ]) + "\n"
      result_payload = base64.b64encode(mode_result.encode()).decode()
      primary.succeed(
          "printf '%s' "
          + shlex.quote(result_payload)
          + " | ${pkgs.coreutils}/bin/base64 -d"
          + " > /tmp/campaign-mode-gate-output/result"
      )
      framed_transcript = (
          transcript
          + "\nAUTHORITATIVE_GATE_RESULT_BEGIN\n"
          + mode_result
          + "AUTHORITATIVE_GATE_RESULT_END\n"
      )
      payload = base64.b64encode(framed_transcript.encode()).decode()
      primary.succeed(
          "printf '%s\\n%s\\n%s\\n' "
          + shlex.quote("CAMPAIGN_MODE_GATE_TRANSCRIPT_BEGIN")
          + " "
          + shlex.quote(payload)
          + " "
          + shlex.quote("CAMPAIGN_MODE_GATE_TRANSCRIPT_END")
          + " > /dev/ttyS0"
      )
      primary.succeed(
          ${builtins.toJSON "printf '%s\\n' CAMPAIGN_MODE_GATE_OUTPUT_BEGIN > /dev/ttyS0; ${pkgs.tar}/bin/tar -C /tmp/campaign-mode-gate-output -cf - . | ${pkgs.coreutils}/bin/base64 >> /dev/ttyS0; printf '%s\\n' CAMPAIGN_MODE_GATE_OUTPUT_END > /dev/ttyS0"}
      )
    '';
  };
in
  assert builtins.elem mode ["disabled" "enabled"];
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-mode-${name}-${mode}";
      version = "0";
      src = null;
      buildDeps = [fleet pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.grep pkgs.tar];
      phases = [
        {
          name = "retain-mode-specific-${name}";
          script = ''
            set -eu
            mkdir -p "$out/authoritative-output"
            serial=$(find ${fleet} -name '*-serial.log' -type f -print -quit)
            test -n "$serial"
            tr -d '\r' < "$serial" > "$TMPDIR/normalized-serial"

            for marker in \
              CAMPAIGN_MODE_GATE_TRANSCRIPT_BEGIN \
              CAMPAIGN_MODE_GATE_TRANSCRIPT_END \
              CAMPAIGN_MODE_GATE_OUTPUT_BEGIN \
              CAMPAIGN_MODE_GATE_OUTPUT_END; do
              test "$(grep -Fxc "$marker" "$TMPDIR/normalized-serial")" -eq 1
            done

            awk '
              /^CAMPAIGN_MODE_GATE_TRANSCRIPT_BEGIN$/ {
                if (state != 0) exit 1
                state = 1
                next
              }
              /^CAMPAIGN_MODE_GATE_TRANSCRIPT_END$/ {
                if (state != 1 || payload_lines != 1) exit 1
                state = 2
                next
              }
              state == 1 { print; payload_lines += 1 }
              END { if (state != 2) exit 1 }
            ' "$TMPDIR/normalized-serial" > "$TMPDIR/transcript-payload"
            printf '%s' "$(cat "$TMPDIR/transcript-payload")" \
              | base64 -d > "$out/transcript"

            awk '
              /^CAMPAIGN_MODE_GATE_OUTPUT_BEGIN$/ {
                if (state != 0) exit 1
                state = 1
                next
              }
              /^CAMPAIGN_MODE_GATE_OUTPUT_END$/ {
                if (state != 1) exit 1
                state = 2
                next
              }
              state == 1 { print }
              END { if (state != 2) exit 1 }
            ' "$TMPDIR/normalized-serial" \
              | base64 -d \
              | tar -xf - -C "$out/authoritative-output"
            test -f "$out/authoritative-output/result"

            test "$(grep -Fxc 'AUTHORITATIVE_GATE_RESULT_BEGIN' "$out/transcript")" -eq 1
            test "$(grep -Fxc 'AUTHORITATIVE_GATE_RESULT_END' "$out/transcript")" -eq 1
            extract_authoritative_result() {
              awk '
                /^AUTHORITATIVE_GATE_RESULT_BEGIN$/ {
                  if (state != 0) exit 1
                  state = 1
                  next
                }
                /^AUTHORITATIVE_GATE_RESULT_END$/ {
                  if (state != 1) exit 1
                  state = 2
                  next
                }
                state == 1 { print }
                END { if (state != 2) exit 1 }
              ' "$1"
            }
            cat > "$TMPDIR/malformed-authoritative-frame" <<'MALFORMED'
            AUTHORITATIVE_GATE_RESULT_END
            AUTHORITATIVE_GATE_RESULT_BEGIN
            PASS
            MALFORMED
            if extract_authoritative_result "$TMPDIR/malformed-authoritative-frame" \
              > "$TMPDIR/malformed-authoritative-result"; then
              echo "malformed authoritative frame was accepted" >&2
              exit 1
            fi
            extract_authoritative_result "$out/transcript" \
              > "$TMPDIR/authoritative-result"
            cmp "$TMPDIR/authoritative-result" "$out/authoritative-output/result"
            {
              cat "$TMPDIR/authoritative-result"
              printf '%s\n' \
                'executor_derivation=${fleet}'
            } > "$out/raw-result"
            grep -Fxq PASS "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg authoritativeResultIdentity} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "campaign_mode=${mode}"} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "campaign_configuration_identity=${expectedConfigurationIdentity}"} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "campaign_toplevel=${toplevel}"} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "executor_derivation=${fleet}"} "$out/raw-result"
            {
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_BEGIN'
              cat "$out/raw-result"
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_END'
            } >> "$out/transcript"

            cat > "$out/result" <<RESULT
            PASS
            gate=${gateName}
            authoritative_attr=${authoritativeAttr}
            execution_family=${executionFamily}
            campaign_mode=${mode}
            campaign_configuration_identity=${expectedConfigurationIdentity}
            campaign_toplevel=${toplevel}
            executor_derivation=${fleet}
            retained=true
            RESULT
          '';
        }
      ];
    }
