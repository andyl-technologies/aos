##! Correlates real native recovery with digest-bound Crucible acknowledgements.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  adapterSocket = "/run/aos/ability-crucible/controller.sock";
  executorSocket = "/run/aos-instrumentation/controller.sock";
  cruciblePolicy = builtins.path {
    path = ./_crucible-baseline-policy.nix;
    name = "aos-crucible-baseline-policy.nix";
  };
  crucibleModule = {
    aos.profiles.abilityCrucible.enable = true;
  };
  crucibleHostModule = ''
    imports = [ ${builtins.toJSON (builtins.toString cruciblePolicy)} ];
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
  disabledConfig = disabled.machines.runtime.system.config;
  enabledConfig = base.machines.runtime.system.config;
  adapterPath = toString pkgs.aos-ability-crucible;
  disabledPackages = map toString disabledConfig.environment.systemPackages;
  enabledPackages = map toString enabledConfig.environment.systemPackages;
  evaluationContract = assert !(builtins.elem adapterPath disabledPackages);
  assert builtins.elem adapterPath enabledPackages;
  assert enabledConfig.aos.execution.observer.socketPath == executorSocket;
  assert enabledConfig.aos.tests.executionObserver.forwardSocketPath == adapterSocket;
  assert enabledConfig.aos.abilityCrucible.activationOwner == "manager"; true;
in
  assert evaluationContract;
    base
    // {
      name = "ability-crucible-baseline";
      machines.runtime =
        base.machines.runtime
        // {
          extraClosures = base.machines.runtime.extraClosures ++ [disabledConfig.system.build.toplevel];
        };
      testScript =
        base.testScript
        +
        # python
        ''
          runtime.succeed(f"{SYSTEMCTL} is-active --quiet aos-ability-crucible.service")
          assert runtime.succeed(f"{COREUTILS}/stat --format=%U:%G:%a /run/aos/ability-crucible").strip() == "root:root:700"
          runtime.succeed("test -S ${adapterSocket}")

          # Findings contain checked journal projections and independently
          # observed HTTP state from the actual interruption flights. Adapter
          # acknowledgements bind marker delivery to those exact event bytes;
          # neither marker delivery nor a retained result claims live state.
          findings = {}
          for sequence in ("process-loss", "power-loss"):
              recovery = RECOVERY_FINDINGS[sequence]
              for retained in (recovery["held"], recovery["resumed"]):
                  event = retained["event"]
                  payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
                  event_digest = "sha256:" + hashlib.sha256(b"aos.activation.boundary\0" + payload).hexdigest()
                  assert retained["event_digest"] == event_digest, retained
                  assert retained["forwarded_acknowledgement"] == {
                      "action": "continue", "event_digest": event_digest,
                      "schema": "aos.activation.boundary-ack",
                  }, retained
              assert recovery["after"]["pending"] is None
              assert recovery["after"]["completed"] is not None
              assert recovery["after"]["liveStateVerified"] is False
              assert recovery["substrate"]["beforeResponse"] != recovery["substrate"]["afterResponse"]
              findings[sequence] = {
                  "schema": "aos.crucible.native-recovery-finding",
                  "selection": recovery["held"]["event"],
                  "held": recovery["held"], "resumed": recovery["resumed"],
                  "checkedJournalRecords": recovery["records"],
                  "checkedCompletion": recovery["after"]["completed"],
                  "boundaries": recovery["boundaries"],
                  "substrate": recovery["substrate"],
              }
          finding_path = f"{BOUNDARY_ROOT}/crucible-baseline-finding.json"
          write_canonical(finding_path, {"schema": "aos.crucible.native-recovery-findings", "flights": findings})
          assert read_json(finding_path)["flights"] == findings

          runtime.fail(
              f"{NIX_STORE} --query --requisites ${disabledConfig.system.build.toplevel} "
              "| ${pkgs.grep}/bin/grep -E '(aos-ability-crucible|crucible-guest)'"
          )
        '';
    }
