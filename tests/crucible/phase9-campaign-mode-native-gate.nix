{
  pkgs,
  lib,
  testing,
  mode,
  system,
  gate,
  authoritativeAttr,
  authoritativeResultIdentity ? "gate=${gate}",
  authority,
  name,
  cargoBuildCommands,
  installedTests,
  runtimeCommands,
  executionFamily ? "native-runtime",
  # Retained for callers: prebuilt executables always keep their native
  # library references.
  sqliteRequired ? false,
}: let
  testGate = import ./_test-gate.nix {inherit pkgs lib;};
  inherit (testGate) workspaceTests;

  # Each Cargo command builds one package selection. An installed test is
  # that selection's prebuilt harness for one target, so the guest receives
  # the executable the authoritative family compiled instead of a private
  # rebuild.
  words = command: builtins.filter (word: word != "") (lib.splitString " " command);
  # Drops target flags and build-only options, keeping the selection.
  selectionWords = command:
    (lib.foldl' (state: word:
      if state.skip
      then state // {skip = false;}
      else if word == "--test"
      then state // {skip = true;}
      else if builtins.elem word ["test" "--frozen" "--offline" "--no-run" "--lib" "-j$NIX_BUILD_CORES"]
      then state
      else state // {kept = state.kept ++ [word];}) {
      skip = false;
      kept = [];
    } (words command)).kept;
  commandPackage = command: let
    commandWords = words command;
    index = lib.lists.findFirstIndex (word: word == "-p") null commandWords;
  in
    builtins.elemAt commandWords (index + 1);
  commandFor = test: let
    matching = builtins.filter (command: commandPackage command == test.crateDir) cargoBuildCommands;
    target =
      if test.targetKind == "test"
      then "--test ${test.targetName}"
      else "--lib";
  in
    assert builtins.length matching == 1; "test ${lib.concatStringsSep " " (selectionWords (builtins.head matching))} ${target}";
  release = builtins.any (command: builtins.elem "--release" (words command)) cargoBuildCommands;
  executor = testGate.mkCrucibleBinaries {
    pname = "crucible-${name}-mode-executor";
    builds =
      if release
      then [workspaceTests.apacheRelease workspaceTests.gplRelease]
      else testGate.debugBuilds;
    executables = builtins.listToAttrs (map (test: {
        name = test.destination;
        value = commandFor test;
      })
      installedTests);
  };
  expectedConfigurationIdentity = system.config.aos.crucibleCampaign._runtimeIdentity;
  toplevel = system.config.system.build.toplevel;
  commands =
    map (command: {
      executable = "${executor}/bin/${command.executable}";
      inherit (command) arguments evidence expectedCount;
    })
    runtimeCommands;
  fleet = testing.mkFleetTest {
    name = "crucible-campaign-mode-${name}-${mode}";
    timeout = 1800;
    machines.primary = {
      inherit system;
      memoryMiB = 4096;
      varSizeMiB = 4096;
      extraClosures = [executor pkgs.crucible];
    };
    testScript = ''
      import base64
      import json
      import os
      import shlex

      ${builtins.readFile ./_phase9-campaign-mode-libtest.py}

      mode = ${builtins.toJSON mode}
      executor_derivation = os.environ["out"]
      expected_identity = ${builtins.toJSON expectedConfigurationIdentity}
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

      commands = json.loads(${builtins.toJSON (builtins.toJSON commands)})
      transcripts = []
      evidence = []
      for command_spec in commands:
          command, transcript, passed_evidence = run_campaign_mode_test(
              command_spec["executable"],
              command_spec["arguments"],
              command_spec["evidence"],
              command_spec["expectedCount"],
              primary.succeed,
          )
          transcripts.append(f"$ {command}\n{transcript}")
          evidence.append(passed_evidence)

      raw_result = "\n".join([
          "PASS",
          ${builtins.toJSON "gate=${gate}"},
          *evidence,
          f"campaign_mode={mode}",
          f"campaign_configuration_identity={identity}",
          f"campaign_toplevel={composition_toplevel}",
          f"machine_toplevel={actual_toplevel}",
          f"executor_derivation={executor_derivation}",
          ${builtins.toJSON "test_executor_derivation=${executor}"},
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
  assert authority.type == "derivation";
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-mode-${name}-${mode}";
      version = "0";
      src = null;
      passthru.campaignModeReceipt = {
        schemaVersion = 1;
        executor = fleet;
        inherit mode gate toplevel;
        configurationIdentity = expectedConfigurationIdentity;
      };
      buildDeps = [authority fleet pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.grep];
      phases = [
        {
          name = "retain-mode-specific-${name}";
          script = ''
            set -eu
            mkdir -p "$out"
            test "$(grep -Fxc PASS ${authority}/result)" -eq 1
            test "$(grep -Fxc ${lib.escapeShellArg authoritativeResultIdentity} ${authority}/result)" -eq 1
            serial=$(find ${fleet} -name '*-serial.log' -type f -print -quit)
            test -n "$serial"
            normalized_serial="$TMPDIR/campaign-mode-serial"
            tr -d '\r' < "$serial" > "$normalized_serial"
            test "$(grep -Fxc 'CAMPAIGN_MODE_GATE_TRANSCRIPT_BEGIN' "$normalized_serial")" -eq 1
            test "$(grep -Fxc 'CAMPAIGN_MODE_GATE_TRANSCRIPT_END' "$normalized_serial")" -eq 1
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
            ' "$normalized_serial" > "$TMPDIR/transcript-payload"
            printf '%s' "$(cat "$TMPDIR/transcript-payload")" \
              | base64 -d > "$out/transcript"
            test "$(grep -Fxc 'CAMPAIGN_GATE_RESULT_BEGIN' "$out/transcript")" -eq 1
            test "$(grep -Fxc 'CAMPAIGN_GATE_RESULT_END' "$out/transcript")" -eq 1
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
            ' "$out/transcript" > "$out/raw-result"
            grep -Fxq PASS "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "gate=${gate}"} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "campaign_mode=${mode}"} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "campaign_toplevel=${toplevel}"} "$out/raw-result"
            grep -Fxq ${lib.escapeShellArg "executor_derivation=${fleet}"} "$out/raw-result"
            test "$(grep -Fxc PASS "$out/raw-result")" -eq 1
            test "$(grep -Fxc ${lib.escapeShellArg "gate=${gate}"} "$out/raw-result")" -eq 1
            test "$(grep -Fxc ${lib.escapeShellArg "campaign_mode=${mode}"} "$out/raw-result")" -eq 1
            test "$(grep -c '^campaign_configuration_identity=' "$out/raw-result")" -eq 1
            test "$(grep -Fxc ${lib.escapeShellArg "campaign_toplevel=${toplevel}"} "$out/raw-result")" -eq 1
            test "$(grep -Fxc ${lib.escapeShellArg "machine_toplevel=${fleet.machineSystems.primary.config.system.build.toplevel}"} "$out/raw-result")" -eq 1
            test "$(grep -Fxc ${lib.escapeShellArg "executor_derivation=${fleet}"} "$out/raw-result")" -eq 1

            configuration_identity=$(sed -n \
              's/^campaign_configuration_identity=//p' "$out/raw-result")
            test -n "$configuration_identity"
            cat > "$out/result" <<RESULT
            PASS
            gate=${gate}
            authoritative_attr=${authoritativeAttr}
            authoritative_derivation=${authority}
            execution_family=${executionFamily}
            campaign_mode=${mode}
            campaign_configuration_identity=$configuration_identity
            campaign_toplevel=${toplevel}
            executor_derivation=${fleet}
            test_executor_derivation=${executor}
            exact_aggregate_selectors_executed=true
            retained_transcript=true
            RESULT
          '';
        }
      ];
    }
