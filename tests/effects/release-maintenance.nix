##! Checks native release maintenance roles, private credentials, retention, schedules, and boot activation.
let
  repo = ../..;
  lib = import (repo + /lib) {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "native-service-fixture";
    outPath = builtins.toString (import ./_fixture-payload.nix "native-service");
    meta.mainProgram = "native-handler";
  };
  evaluate = enabled: overrides:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [
        overrides
        (repo + /lib/effects/module.nix)
        (repo + /pkgs/system/_service-management/module.nix)
        (repo + /pkgs/filesystem/_aos-filesystem-provider/module.nix)
        (repo + /pkgs/system/_systemd-abilities/resource-handlers.nix)
        (repo + /pkgs/tools/aos/_abilities/release-coordinator/module.nix)
        (repo + /pkgs/tools/aos/_abilities/control-plane/module.nix)
        ({lib, ...}: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
              description = "Fixture assertions.";
            };
            aos.boot.preparationExecutable = lib.mkOption {
              type = lib.types.str;
              default = "${package}/bin/aos-boot-prepare";
              description = "Native boot fixture.";
            };
            aos.packageRuntime.configurationEvaluation.nixStoreExecutable = lib.mkOption {
              type = lib.types.str;
              default = "${package}/bin/nix-store";
              description = "Pinned fixture.";
            };
          };
          config = {
            aos.activation.scope = ["fixture" "host"];
            aos.config.unitGraph.enable = true;
            aos.release.coordinator = {
              enable = enabled;
              releaseProgram = {path = "${package}/bin/release";};
              timestampProgram = {path = "${package}/bin/timestamp";};
              backupProgram = {path = "${package}/bin/backup";};
              restoreCheckProgram = {path = "${package}/bin/restore";};
              alertCheckProgram = {path = "${package}/bin/alert-check";};
              fitnessCredentials = {fitness = "fitness-secret";};
              alertProgram = {path = "${package}/bin/alert";};
              releaseCredentials = {release = "release-secret";};
              timestampCredentials = {timestamp = "timestamp-secret";};
              backupCredentials = {backup = "backup-secret";};
              alertCredentials = {alert = "alert-secret";};
            };
            aos.abilities = {
              serviceManagement.operations.realize.handler.program = package;
              identity.operations.group.handler.program = package;
              identity.operations.principal.handler.program = package;
              network.operations.ready.handler.program = package;
            };
          };
        })
      ];
    };
  evaluated = evaluate true {};
  graph = evaluated.config.aos.activation.graph;
  nodes = builtins.attrValues graph.nodes;
  effectsFor = ability: operation: builtins.filter (node: builtins.elem ability node.identity && builtins.elem operation node.identity) nodes;
  serviceFor = name: builtins.head (builtins.filter (node: builtins.elem name node.identity) (effectsFor "serviceManagement" "realize"));
  release = serviceFor "release-coordinator.release";
  activate = serviceFor "control-plane.aos-activate";
  timestamp = builtins.head (builtins.filter (node: builtins.elem "release-coordinator.timestamp" node.identity) (effectsFor "scheduledActivation" "ensure"));
  disabled = evaluate false {};
  timestampDisabled = evaluate true {
    aos.services."release-coordinator.timestamp".enable = lib.mkForce false;
  };
  overridden = timestampDisabled.config.aos.abilities;
  overrideGraph = timestampDisabled.config.aos.activation.graph;
in
  assert builtins.all (item: item.assertion) evaluated.config.assertions;
  assert builtins.length graph.order == builtins.length nodes;
  assert builtins.all (node: node.lifetime == "persistent") ((effectsFor "identity" "group") ++ (effectsFor "identity" "principal") ++ (effectsFor "filesystem" "persistentAllocate"));
  assert builtins.length (effectsFor "scheduledActivation" "ensure") == 4;
  assert (serviceFor "release-coordinator.alert-check").input.identity.file_creation_mask == "0027";
  assert (serviceFor "release-coordinator.alert-check").input.isolation.temporary_filesystems
  == [
    {
      path = "/var/lib/aos-release-coordinator";
      read_only = true;
    }
  ];
  assert builtins.length (serviceFor "release-coordinator.restore-check").input.credentials.views == 1;
  assert timestamp.input.target._type == "aos-effect-output";
  assert timestamp.input.target.output == "resource";
  assert release.input.policy.hardening.operation_deny == ["mount" "reboot" "swap"];
  assert !release.input.auto_start;
  assert release.input.credentials.views != [];
  assert (builtins.head release.input.credentials.views).reference.output == "path";
  assert activate.input.manager_identity.name == "aos-activate";
  assert (builtins.head activate.input.lifecycle.start).executable.arguments == ["apply-deployment" "--input" "/usr/lib/aos/host/deployment" "--state-directory" "/var/lib/profiles/system/deployment" "--nix-store" "${package}/bin/nix-store"];
  assert builtins.length (builtins.attrNames disabled.config.aos.activation.graph.nodes) == 1;
  assert !(overridden.scheduledActivation.operations.ensure.effects ? "release-coordinator.timestamp");
  assert !(overridden.filesystem.operations.allocate.effects ? "release-coordinator.timestamp-runtime");
  assert overridden.filesystem.operations.persistentAllocate.effects ? "release-coordinator.timestamp-state";
  assert !(overridden.credential.operations.deliver.effects ? "release-coordinator.timestamp-timestamp");
  assert builtins.length overrideGraph.order == builtins.length (builtins.attrNames overrideGraph.nodes);
    builtins.deepSeq graph {nativeMaintenanceServices = true;}
