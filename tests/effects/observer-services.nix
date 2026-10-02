##! Native observer services preserve protected endpoints and lifecycle controls.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "observer-fixture";
    outPath = import ./_fixture-payload.nix "observer-fixture";
    meta.mainProgram = "observer-fixture";
  };
  evaluate = settings:
    lib.evalModules {
      inherit lib;
      specialArgs = {
        inherit package;
        packageName = "observer-fixture";
        packageVersion = "1";
        dependencies = {};
      };
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
        ../../pkgs/tools/_aos-ability-crucible/module.nix
        ../../pkgs/tests/_aos-ability-boundary-observer/module.nix
        ({lib, ...}: {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.anything;
            default = [];
          };
          config.aos.abilities = {
            serviceManagement.operations.realize.handler.program = package;
            configuration.operations.file.handler.program = package;
          };
        })
        settings
      ];
    };
  managerOwned = evaluate {
    aos.abilityCrucible.activationOwner = "manager";
    aos.tests.executionObserver.activationOwner = "manager";
  };
  managed = evaluate {aos.abilityCrucible.enable = false;};
  external = evaluate {
    aos.abilityCrucible.enable = false;
    aos.tests.executionObserver.mode = "external-test-mount";
  };
  forwarded = evaluate {
    aos.abilityCrucible.enable = false;
    aos.tests.executionObserver.forwardSocketPath = "/run/aos/ability-crucible/controller.sock";
  };
  disabled = evaluate {
    aos.abilityCrucible.enable = false;
    aos.tests.executionObserver.enable = false;
  };
  crucible = evaluate {aos.tests.executionObserver.enable = false;};
  select = evaluated: key: builtins.head (builtins.filter (node: builtins.elem key node.identity) (builtins.attrValues evaluated.config.aos.activation.graph.nodes));
  controller = (select managed "boundary-observer.controller").input;
  adapter = (select crucible "ability-crucible.adapter").input;
  adapterConfig = (select crucible "ability-crucible").input;
  socket = builtins.head controller.socket_activation.sockets;
in {
  managerBootstrapOwnsDirectories = builtins.length managerOwned.config.aos.tests.executionObserver.bootstrap.directories == 2 && builtins.length managerOwned.config.aos.abilityCrucible.bootstrap.directories == 1;
  managerBootstrapRetainsCanonicalConfiguration = (builtins.head managerOwned.config.aos.abilityCrucible.bootstrap.files).content == (select managerOwned "ability-crucible").input.content;
  managerServicesHaveNoInactiveDirectoryReferences = (select managerOwned "boundary-observer.controller").input.activation_owner == "manager" && (select managerOwned "boundary-observer.controller").dependencies == [] && (select managerOwned "ability-crucible.adapter").dependencies == [];
  disabledHasNoEffects = disabled.config.aos.activation.graph.nodes == {} && disabled.config.aos.execution.observer == null;
  externalHasNoManagedEffects = external.config.aos.activation.graph.nodes == {};
  externalUsesExplicitEndpoint = external.config.aos.execution.observer.socketPath == "/run/aos-instrumentation/controller.sock";
  managedPreservesCommand =
    (builtins.head controller.lifecycle.start).executable
    == {
      path = "${package}/bin/aos-ability-boundary-controller";
      arguments = ["serve" "--socket" "/run/aos-instrumentation/controller.sock"];
    };
  managedPreservesRestart = controller.lifecycle.restart == "on-failure" && controller.lifecycle.restart_delay_millis == 1000;
  managedPreservesProtectedSocket = socket.mode == "0600" && socket.remove_on_stop && (builtins.head socket.endpoints).path == "/run/aos-instrumentation/controller.sock";
  managedPreservesState = (select managed "boundary-observer-state").lifetime == "persistent";
  forwardedUsesExplicitEndpoint = (select forwarded "boundary-observer.controller").input.environment.variables.AOS_ABILITY_FORWARD_SOCKET == "/run/aos/ability-crucible/controller.sock";
  adapterPreservesReadiness = adapter.readiness.mechanism == "process-running" && adapter.lifecycle.start_timeout_millis == 30000 && (builtins.head adapter.lifecycle.post_start).executable.arguments == ["--wait-ready" "/run/aos/ability-crucible/controller.sock"];
  adapterPreservesIsolation = adapter.identity.file_creation_mask == "0077" && adapter.isolation.filesystem == "read-only-system" && adapter.supervision.notification_access == "none";
  adapterWaitsForConfigurationAndRuntime = builtins.length (select crucible "ability-crucible.adapter").dependencies == 2;
  adapterRetainsCanonicalConfiguration = (builtins.fromJSON adapterConfig.content).schema == "aos.ability-crucible-adapter/v1" && adapterConfig.mode == "0400";
}
