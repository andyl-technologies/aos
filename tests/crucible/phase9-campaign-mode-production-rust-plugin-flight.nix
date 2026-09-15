{
  pkgs,
  lib,
  testing,
  mode,
  system,
  productionGate,
}: let
  toplevel = system.config.system.build.toplevel;
  inherit (productionGate.passthru) rootfsDeps testScript;
  fleet = testing.mkFleetTest {
    name = "crucible-campaign-mode-production-flight-${mode}";
    timeout = 3600;
    machines.primary = {
      inherit system;
      memoryMiB = 8192;
      varSizeMiB = 12288;
      extraClosures = rootfsDeps;
    };
    testScript = ''
      import base64
      import shlex

      mode = ${builtins.toJSON mode}
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

      output = primary.succeed(
          ${builtins.toJSON "${pkgs.bash}/bin/bash"}
          + " -c "
          + shlex.quote(${builtins.toJSON testScript}),
          timeout=3300,
      )
      payload = base64.b64encode(output.encode()).decode()
      identity_payload = base64.b64encode(identity.encode()).decode()
      primary.succeed(
          "printf '%s\\n%s\\n%s\\n%s\\n' "
          + shlex.quote("CAMPAIGN_MODE_FLIGHT_BEGIN")
          + " "
          + shlex.quote(identity_payload)
          + " "
          + shlex.quote(payload)
          + " "
          + shlex.quote("CAMPAIGN_MODE_FLIGHT_END")
          + " > /dev/ttyS0"
      )
    '';
  };
in
  assert builtins.elem mode ["disabled" "enabled"];
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-mode-production-flight-${mode}";
      version = "0";
      src = null;
      buildDeps = [fleet pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.grep];
      phases = [
        {
          name = "retain-mode-specific-production-flight";
          script = ''
            set -eu
            mkdir -p "$out"
            serial=$(find ${fleet} -name '*-serial.log' -type f -print -quit)
            test -n "$serial"
            tr -d '\r' < "$serial" > "$TMPDIR/normalized-serial"
            . ${./_phase9-campaign-mode-frame.sh}
            extract_campaign_mode_frame \
              "$TMPDIR/normalized-serial" \
              CAMPAIGN_MODE_FLIGHT_BEGIN \
              CAMPAIGN_MODE_FLIGHT_END \
              2 \
              "$TMPDIR/flight-frame"
            identity_payload=$(sed -n '1p' "$TMPDIR/flight-frame")
            transcript_payload=$(sed -n '2p' "$TMPDIR/flight-frame")
            test -n "$identity_payload"
            test -n "$transcript_payload"
            printf '%s' "$identity_payload" | base64 -d > "$TMPDIR/identity"
            printf '%s' "$transcript_payload" | base64 -d > "$out/transcript"
            configuration_identity=$(cat "$TMPDIR/identity")
            test -n "$configuration_identity"

            for evidence in \
              PASS \
              gate=gate:production-rust-plugin-flight \
              component_failures=0 \
              sample_stream_restart_identical=true \
              idle_wake_stream_restart_identical=true \
              production_host_parallel_state_identity=true \
              production_host_parallel_time_identity=true \
              production_host_parallel_canonical_log_identity=true \
              production_host_parallel_authenticated_exact_recovery=true; do
              grep -Fxq "$evidence" "$out/transcript"
            done
            extract_campaign_mode_result_frame \
              "$out/transcript" \
              PRODUCTION_PLUGIN_RESULT_BEGIN \
              PRODUCTION_PLUGIN_RESULT_END \
              "$TMPDIR/gate-evidence"
            for evidence in \
              PASS \
              gate=gate:production-rust-plugin-flight \
              component_failures=0 \
              sample_stream_restart_identical=true \
              idle_wake_stream_restart_identical=true; do
              test "$(grep -Fxc "$evidence" "$TMPDIR/gate-evidence")" -eq 1
            done
            {
              cat "$TMPDIR/gate-evidence"
              printf '%s\n' \
                'campaign_mode=${mode}' \
                "campaign_configuration_identity=$configuration_identity" \
                'campaign_toplevel=${toplevel}' \
                'executor_derivation=${fleet}'
            } > "$out/raw-result"
            {
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_BEGIN'
              cat "$out/raw-result"
              printf '%s\n' 'CAMPAIGN_GATE_RESULT_END'
            } >> "$out/transcript"

            cat > "$out/result" <<RESULT
            PASS
            gate=gate:production-rust-plugin-flight
            authoritative_attr=checks.crucible.phase7.productionRustPluginFlight
            execution_family=qemu-runtime
            campaign_mode=${mode}
            campaign_configuration_identity=$configuration_identity
            campaign_toplevel=${toplevel}
            executor_derivation=${fleet}
            exact_production_flight_executed=true
            retained_transcript=true
            RESULT
          '';
        }
      ];
    }
