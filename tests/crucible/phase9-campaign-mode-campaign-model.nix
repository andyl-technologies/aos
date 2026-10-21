{
  pkgs,
  lib,
  testing,
  mode,
  system,
}: let
  testGate = import ./_test-gate.nix {inherit pkgs lib;};
  # The guest runs the release harnesses compiled once by the release family.
  executor = testGate.mkCrucibleBinaries {
    pname = "crucible-campaign-model-mode-executor";
    builds = [testGate.workspaceTests.apacheRelease];
    executables = {
      campaign-lib = "test --release -p crucible-campaign --lib";
      gate-campaign-model = "test --release -p crucible-campaign --test gate_campaign_model";
      crucible-lib = "test --release -p crucible --features test-support --lib";
      daemon-lib = "test --release -p crucible-daemon --lib";
    };
  };
  toplevel = system.config.system.build.toplevel;
  fleet = testing.mkFleetTest {
    name = "crucible-campaign-mode-campaign-model-${mode}";
    timeout = 1800;
    machines.primary = {
      inherit system;
      memoryMiB = 4096;
      varSizeMiB = 4096;
      extraClosures = [executor pkgs.crucible];
    };
    testScript = ''
      import base64
      import shlex

      ${builtins.readFile ./_phase9-campaign-mode-libtest.py}

      mode = ${builtins.toJSON mode}
      expected_toplevel = ${builtins.toJSON (toString fleet.machineSystems.primary.config.system.build.toplevel)}
      composition_toplevel = ${builtins.toJSON (toString toplevel)}
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

      commands = [
          (
              ${builtins.toJSON "${executor}/bin/campaign-lib"},
              [], "campaign_lib", None,
          ),
          (
              ${builtins.toJSON "${executor}/bin/gate-campaign-model"},
              [], "campaign_model_integration", None,
          ),
          (
              ${builtins.toJSON "${executor}/bin/crucible-lib"},
              ["--exact", "model::measurement::runtime::tests::model_sources_project_exact_replay_samples"],
              "model_sample_projection", 1,
          ),
          (
              ${builtins.toJSON "${executor}/bin/daemon-lib"},
              ["--exact", "crucible_measurement::evidence::tests::v3_publication_round_trips_and_rederives_guest_and_model_samples"],
              "mixed_guest_model_raw_replay", 1,
          ),
          (
              ${builtins.toJSON "${executor}/bin/daemon-lib"},
              ["--exact", "crucible_measurement::tests::verified_crucible_aggregate_drives_exact_campaign_objective"],
              "verified_model_owned_objective", 1,
          ),
      ]
      transcripts = []
      evidence = []
      for executable, arguments, evidence_key, expected_count in commands:
          command, transcript, passed_evidence = run_campaign_mode_test(
              executable, arguments, evidence_key, expected_count, primary.succeed
          )
          transcripts.append(transcript)
          evidence.append(passed_evidence)

      raw_result = "\n".join([
          "PASS",
          "gate=gate:campaign-model",
          *evidence,
          f"campaign_mode={mode}",
          f"campaign_configuration_identity={identity}",
          f"campaign_toplevel={composition_toplevel}",
          f"machine_toplevel={actual_toplevel}",
      ]) + "\n"
      transcript = "\n--- command ---\n".join(transcripts)
      transcript += "\nCAMPAIGN_GATE_RESULT_BEGIN\n"
      transcript += raw_result
      transcript += "CAMPAIGN_GATE_RESULT_END\n"
      payload = base64.b64encode(transcript.encode()).decode()
      primary.succeed(
          "printf '%s\\n%s\\n%s\\n' "
          + shlex.quote("CAMPAIGN_MODE_GATE_TRANSCRIPT_BEGIN")
          + " "
          + shlex.quote(payload)
          + " "
          + shlex.quote("CAMPAIGN_MODE_GATE_TRANSCRIPT_END")
          + " > /dev/ttyS0"
      )
    '';
  };
in
  assert builtins.elem mode ["disabled" "enabled"];
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-mode-campaign-model-${mode}";
      version = "0";
      src = null;
      buildDeps = [fleet pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.grep];
      phases = [
        {
          name = "retain-mode-specific-campaign-model";
          script = ''
            set -eu
            serial=$(find ${fleet} -name '*-serial.log' -type f -print -quit)
            test -n "$serial"
            tr -d '\r' < "$serial" > "$TMPDIR/normalized-serial"
            . ${./_phase9-campaign-mode-frame.sh}
            extract_campaign_mode_frame \
              "$TMPDIR/normalized-serial" \
              CAMPAIGN_MODE_GATE_TRANSCRIPT_BEGIN \
              CAMPAIGN_MODE_GATE_TRANSCRIPT_END \
              1 \
              "$TMPDIR/transcript-frame"
            payload=$(cat "$TMPDIR/transcript-frame")
            test -n "$payload"
            printf '%s' "$payload" | base64 -d > "$TMPDIR/vm-transcript"
            extract_campaign_mode_result_frame \
              "$TMPDIR/vm-transcript" \
              CAMPAIGN_GATE_RESULT_BEGIN \
              CAMPAIGN_GATE_RESULT_END \
              "$TMPDIR/gate-evidence"
            test "$(grep -Fxc PASS "$TMPDIR/gate-evidence")" -eq 1
            test "$(grep -Fxc 'gate=gate:campaign-model' "$TMPDIR/gate-evidence")" -eq 1
            test "$(grep -Fxc 'campaign_mode=${mode}' "$TMPDIR/gate-evidence")" -eq 1
            test "$(grep -Fxc 'campaign_toplevel=${toplevel}' "$TMPDIR/gate-evidence")" -eq 1
            test "$(grep -Fxc 'machine_toplevel=${fleet.machineSystems.primary.config.system.build.toplevel}' "$TMPDIR/gate-evidence")" -eq 1

            configuration_identity=$(sed -n \
              's/^campaign_configuration_identity=//p' "$TMPDIR/gate-evidence")
            test -n "$configuration_identity"
            test "$(grep -c '^campaign_configuration_identity=' "$TMPDIR/gate-evidence")" -eq 1
            mkdir -p "$out"
            {
              cat "$TMPDIR/gate-evidence"
              printf '%s\n' 'executor_derivation=${fleet}'
            } > "$out/raw-result"
            awk '
              /^CAMPAIGN_GATE_RESULT_BEGIN$/ { state = 1; next }
              /^CAMPAIGN_GATE_RESULT_END$/ { state = 2; next }
              state != 1 { print }
            ' "$TMPDIR/vm-transcript" > "$out/transcript"
            {
              printf '%s\n' CAMPAIGN_GATE_RESULT_BEGIN
              cat "$out/raw-result"
              printf '%s\n' CAMPAIGN_GATE_RESULT_END
            } >> "$out/transcript"
            cat > "$out/result" <<RESULT
            PASS
            gate=gate:campaign-model
            authoritative_attr=checks.crucible.phase1.gates.campaignModel
            execution_family=native-runtime
            campaign_mode=${mode}
            campaign_configuration_identity=$configuration_identity
            campaign_toplevel=${toplevel}
            executor_derivation=${fleet}
            exact_aggregate_selectors_executed=true
            retained_transcript=true
            RESULT
          '';
        }
      ];
    }
