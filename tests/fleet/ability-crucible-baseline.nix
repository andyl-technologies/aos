##! Baseline Crucible instrumentation over real native nginx recovery.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  adapterSocket = "/run/aos/ability-crucible/crucible.sock";
  executorSocket = "/run/aos-instrumentation/controller.sock";
  crucibleModule = {
    aos.profiles.abilityCrucible.enable = true;
    aos.services.abilityCrucible.socketName = "crucible.sock";
  };
  crucibleHostModule = ''
    aos.profiles.abilityCrucible.enable = true;
    aos.services.abilityCrucible.socketName = "crucible.sock";
  '';
  disabled = import ./runtime-module-composition.nix {
    inherit lib mkSystem pkgs qualificationImage;
  };
  base = import ./runtime-module-composition.nix {
    inherit lib mkSystem pkgs qualificationImage;
    forwardObserverToCrucible = true;
    extraRuntimeModules = [crucibleModule];
    extraHostModule = crucibleHostModule;
    additionalClosures = [pkgs.aos-ability-crucible];
  };
  disabledSystem = disabled.machines.runtime.system;
  enabledSystem = base.machines.runtime.system;
  disabledConfig = disabledSystem.config;
  enabledConfig = enabledSystem.config;
  adapterPath = toString pkgs.aos-ability-crucible;
  disabledPackages = map toString disabledConfig.environment.systemPackages;
  enabledPackages = map toString enabledConfig.environment.systemPackages;
  evaluationContract = assert !(builtins.elem adapterPath disabledPackages);
  assert builtins.elem adapterPath enabledPackages;
  assert enabledConfig.aos.abilities.executionObserver
  == {
    request = "aos-ability-boundary-observer:endpoint";
    resourceOutput = "resource";
    socketOutput = "socket-path";
  };
  assert enabledConfig.aos.abilities.requests."aos-ability-crucible:observer-endpoint".parameters.endpoint == "default";
  assert enabledConfig.aos.abilities.requests."aos-ability-boundary-observer:forward-endpoint".parameters.endpoint == "default";
  assert enabledConfig.aos.abilities.requests."aos-ability-boundary-observer:endpoint".parameters.socket_path == executorSocket; true;
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
              "test \"$(stat -c '%U:%G:%a' /run/aos/ability-crucible)\" "
              "= root:root:700"
          )
          runtime.succeed("test -S ${adapterSocket}")

          selected_fault = read_json(TARGET)
          reached_fault = read_json(HELD_EVENT)
          reproduced_recovery = read_json(RESUMED_EVENT)
          power_boundary_events = boundary_events(
              power_state["transaction"],
              power_state["plan"],
              publish_selector,
          )
          assert selected_fault == {
              "action": "disconnect",
              "boundary": "effect-returned",
              **publish_selector,
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
                  "transaction": process_state["transaction"],
                  "plan": process_state["plan"],
                  "operation": process_state["publish"][1]["key"],
                  "timeline": publish_timeline,
                  "boundary_timeline": boundary_timeline(
                      boundary_events(
                          process_state["transaction"],
                          process_state["plan"],
                          publish_selector,
                      )
                  ),
              },
              "outcome": "reconciled-completed",
          }
          finding_path = f"{BOUNDARY_ROOT}/crucible-baseline-finding.json"
          write_canonical(finding_path, finding)
          observed_finding = read_json(finding_path)
          assert observed_finding == finding
          assert observed_finding["inspector"]["timeline"] == publish_timeline
          assert observed_finding["outcome"] == "reconciled-completed"

          runtime.fail(
              f"{NIX_STORE} --query --requisites "
              "${disabledConfig.system.build.toplevel} "
              f"| {pkgs.grep}/bin/grep -E "
              "'(aos-ability-crucible|crucible-guest)'"
          )
        '';
    }
