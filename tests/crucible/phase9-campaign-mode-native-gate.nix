{
  pkgs,
  lib,
  testing,
  mode,
  system,
  gate,
  authoritativeAttr,
  authority,
  name,
  cargoBuildCommands,
  installedTests,
  runtimeCommands,
  executionFamily ? "native-runtime",
}: let
  source = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
  controllerArtifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
  cargoArtifactContract = controllerArtifacts.passthru.cargoArtifactContract;
  artifacts = pkgs.mkCargoArtifacts {
    pname = "crucible-${name}-mode-artifacts";
    version = "0";
    src = pkgs.mkCargoDummySource {
      srcRoot = ../../crates;
      name = "crucible-${name}-mode-dummy-source";
      cargoRoot = "crates";
    };
    inherit cargoDeps cargoArtifactContract cargoBuildCommands;
    cargoArtifacts = controllerArtifacts;
    cargoEnv = cargoArtifactContract.cargoEnv;
    cargoRoot = "crates";
    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf];
    runtimeDeps = [pkgs.openssl];
  };
  executor = pkgs.mkCargoPackage {
    pname = "crucible-${name}-mode-executor";
    version = "0";
    src = source;
    inherit cargoDeps cargoArtifactContract cargoBuildCommands;
    cargoArtifacts = artifacts;
    cargoEnv = cargoArtifactContract.cargoEnv;
    cargoRoot = "crates";
    installBins = false;
    doCheck = false;
    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf];
    runtimeDeps = [pkgs.openssl];
    postInstall = ''
      set -eu
      messages="$NIX_BUILD_TOP/cargo-build-messages.jsonl"
      mkdir -p "$out/bin"

      install_test() {
        target_name="$1"
        target_kind="$2"
        crate_dir="$3"
        destination="$4"
        matches="$TMPDIR/$destination.matches"
        jq -r --arg name "$target_name" --arg kind "$target_kind" --arg crate_dir "$crate_dir" '
          select(
            .reason == "compiler-artifact"
            and .target.name == $name
            and (.target.kind == [$kind])
            and (.manifest_path | endswith("/" + $crate_dir + "/Cargo.toml"))
            and .profile.test == true
            and .executable != null
          ) | .executable
        ' "$messages" | sort -u > "$matches"
        test "$(wc -l < "$matches" | tr -d ' ')" -eq 1
        executable=$(cat "$matches")
        test -x "$executable"
        cp "$executable" "$out/bin/$destination"
      }

      ${lib.concatMapStringsSep "\n" (test: "install_test ${lib.escapeShellArg test.targetName} ${lib.escapeShellArg test.targetKind} ${lib.escapeShellArg test.crateDir} ${lib.escapeShellArg test.destination}") installedTests}
    '';
  };
  expectedConfigurationIdentity = system.config.aos.services.crucibleCampaign._runtimeIdentity;
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

      mode = ${builtins.toJSON mode}
      executor_derivation = os.environ["out"]
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

      commands = json.loads(${builtins.toJSON (builtins.toJSON commands)})
      transcripts = []
      evidence = []
      for command_spec in commands:
          executable = command_spec["executable"]
          arguments = command_spec["arguments"]
          expected_count = command_spec["expectedCount"]
          list_command = " ".join(
              [shlex.quote(executable)]
              + [shlex.quote(argument) for argument in arguments]
              + ["--list", "--format", "terse"]
          )
          listed = primary.succeed(list_command, timeout=900)
          listed_count = sum(
              1 for line in listed.splitlines() if line.endswith(": test")
          )
          assert listed_count == expected_count, (
              command_spec["evidence"], listed_count, expected_count, listed
          )

          command = " ".join(
              [shlex.quote(executable)]
              + [shlex.quote(argument) for argument in arguments]
              + ["--test-threads=1"]
          )
          transcript = primary.succeed(command, timeout=900)
          transcripts.append(f"$ {command}\n{transcript}")
          evidence.append(f"{command_spec['evidence']}=PASS")

      raw_result = "\n".join([
          "PASS",
          ${builtins.toJSON "gate=${gate}"},
          *evidence,
          f"campaign_mode={mode}",
          f"campaign_configuration_identity={identity}",
          f"campaign_toplevel={actual_toplevel}",
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
      buildDeps = [authority fleet pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.grep];
      phases = [
        {
          name = "retain-mode-specific-${name}";
          script = ''
            set -eu
            mkdir -p "$out"
            grep -Fxq PASS ${authority}/result
            grep -Fxq ${lib.escapeShellArg "gate=${gate}"} ${authority}/result
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
