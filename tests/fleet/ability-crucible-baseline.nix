##! Baseline Crucible instrumentation over real native nginx recovery.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
  adapterSocket = "/run/aos-instrumentation/crucible.sock";
  executorSocket = "/run/aos-instrumentation/controller.sock";
  adapterConfiguration = builtins.toJSON {
    schema = "aos.ability-crucible-adapter/v1";
    socket = adapterSocket;
    ready_command = "${pkgs.systemd}/bin/systemd-notify";
    required_instruction_abi = 1;
    required_marker_kinds = [
      "assertion"
      "coverage"
      "event"
      "lifecycle"
    ];
  };
  executorConfiguration = builtins.toJSON {
    schema = "aos.ability-execution-observer/v1";
    socket = executorSocket;
  };
  crucibleModule = {lib, ...}: {
    aos.profiles.abilityCrucible.enable = true;

    # The test controller holds the digest-bound runtime acknowledgement at
    # the selected fault boundary. Its upstream hop is the production adapter.
    environment.etc."aos/ability-crucible-adapter.json".text = lib.mkForce adapterConfiguration;
    environment.etc."aos/ability-execution-observer.json" = lib.mkForce {
      text = executorConfiguration;
      mode = "0600";
    };
  };
  crucibleHostModule = ''
    aos.profiles.abilityCrucible.enable = true;
    environment.etc."aos/ability-crucible-adapter.json".text = lib.mkForce ${
      builtins.toJSON adapterConfiguration
    };
    environment.etc."aos/ability-execution-observer.json" = lib.mkForce {
      text = ${builtins.toJSON executorConfiguration};
      mode = "0600";
    };
  '';
  base = import ./ability-native-power-loss.nix {
    inherit lib mkSystem pkgs qualificationImage;
    observerForwardSocket = adapterSocket;
    extraRuntimeModules = [crucibleModule];
    extraHostModule = crucibleHostModule;
    additionalClosures = [pkgs.aos-ability-crucible];
  };
  disabledSystem = fixture.runtimeSystem;
  enabledSystem = base.machines.runtime.system;
  disabledConfig = disabledSystem.config;
  enabledConfig = enabledSystem.config;
  adapterPath = toString pkgs.aos-ability-crucible;
  disabledPackages = map toString disabledConfig.environment.systemPackages;
  enabledPackages = map toString enabledConfig.environment.systemPackages;
  evaluationContract = assert !(disabledConfig.systemd.services ? "aos-ability-crucible");
  assert !(disabledConfig.environment.etc ? "aos/ability-crucible-adapter.json");
  assert !(disabledConfig.environment.etc ? "aos/ability-execution-observer.json");
  assert !(builtins.elem adapterPath disabledPackages);
  assert enabledConfig.systemd.services ? "aos-ability-crucible";
  assert enabledConfig.environment.etc ? "aos/ability-crucible-adapter.json";
  assert enabledConfig.environment.etc ? "aos/ability-execution-observer.json";
  assert builtins.elem adapterPath enabledPackages;
  assert enabledConfig.systemd.services."aos-ability-crucible".serviceConfig.RuntimeDirectory == "aos-instrumentation";
  assert enabledConfig.systemd.services."aos-ability-crucible".serviceConfig.RuntimeDirectoryMode == "0700"; true;
in
  assert evaluationContract;
    base
    // {
      name = "ability-crucible-baseline";
      machines.runtime =
        base.machines.runtime
        // {
          extraClosures =
            base.machines.runtime.extraClosures
            ++ [disabledConfig.system.build.toplevel];
        };
      testScript =
        base.testScript
        + # python
        ''
          print("checking the connected Crucible baseline recovery finding")
          runtime.succeed(
              "systemctl is-active --quiet aos-ability-crucible.service"
          )
          runtime.succeed(
              "test \"$(stat -c '%U:%G:%a' /run/aos-instrumentation)\" "
              "= root:root:700"
          )
          runtime.succeed(
              f"{JQ} -e "
              "'.schema == \"aos.ability-crucible-adapter/v1\" "
              "and .socket == \"${adapterSocket}\" "
              "and .required_instruction_abi == 1 "
              "and .required_marker_kinds == "
              "[\"assertion\",\"coverage\",\"event\",\"lifecycle\"]' "
              "/etc/aos/ability-crucible-adapter.json"
          )
          runtime.succeed(
              f"{JQ} -e "
              "'.schema == \"aos.ability-execution-observer/v1\" "
              "and .socket == \"${executorSocket}\"' "
              "/etc/aos/ability-execution-observer.json"
          )

          selected_fault = read_json(TARGET)
          reached_fault = read_json(HELD_EVENT)
          reproduced_recovery = read_json(RESUMED_EVENT)
          power_boundary_events = boundary_events(power_state[1], power_state[2])
          assert selected_fault == {
              "boundary": "effect-returned",
              "operation_key": PUBLISH_OPERATION,
              "purpose": "effect",
              "sequence": "power-loss",
          }, selected_fault
          for retained in (reached_fault, reproduced_recovery):
              acknowledgement = retained["forwarded_acknowledgement"]
              assert acknowledgement == {
                  "action": "continue",
                  "event_digest": retained["event_digest"],
                  "schema": "aos.ability-execution-boundary-ack/v1",
              }, retained

          # The inspector's checked timeline supplies the finding. The test
          # retains the exact selection and adapter acknowledgements beside it
          # so an operator can relate the generic marker opportunity to the
          # durable AOS recovery records without decoding private state.
          finding = {
              "schema": "aos.ability.crucible-baseline-finding/v1",
              "selection": selected_fault,
              "reached": {
                  "event": reached_fault["event"],
                  "event_digest": reached_fault["event_digest"],
                  "adapter_acknowledgement": (
                      reached_fault["forwarded_acknowledgement"]
                  ),
              },
              "reproduced_recovery": {
                  "event": reproduced_recovery["event"],
                  "event_digest": reproduced_recovery["event_digest"],
                  "adapter_acknowledgement": (
                      reproduced_recovery["forwarded_acknowledgement"]
                  ),
                  "boundary_timeline": boundary_timeline(
                      power_boundary_events
                  ),
              },
              "inspector": {
                  "transaction": process_state[1],
                  "plan": process_state[2],
                  "operation": process_state[6],
                  "timeline": process_timeline,
                  "boundary_timeline": boundary_timeline(
                      process_boundary_events
                  ),
              },
              "outcome": "reconciled-completed",
          }
          finding_path = f"{BOUNDARY_ROOT}/crucible-baseline-finding.json"
          write_canonical(finding_path, finding)
          observed_finding = read_json(finding_path)
          assert observed_finding == finding
          assert observed_finding["inspector"]["timeline"] == process_timeline
          assert observed_finding["outcome"] == "reconciled-completed"

          runtime.fail(
              f"{NIX_BIN}/nix-store --query --requisites "
              "${disabledConfig.system.build.toplevel} "
              f"| {pkgs.grep}/bin/grep -E "
              "'(aos-ability-crucible|crucible-guest)'"
          )
        '';
    }
