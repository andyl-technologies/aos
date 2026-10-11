##! Projects actual host effect executors for namespace and rendered-unit checks.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix;
  program = {
    type = "derivation";
    name = "host-activation-fixture";
    outPath = toString (payload "host-activation");
    meta.mainProgram = "handler";
  };
  evaluation = lib.evalModules {
    inherit lib;
    specialArgs.package.outputs.apm = program.outPath;
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/system/_service-management/module.nix
      ../../pkgs/tools/aos/_abilities/control-plane/module.nix
      ../../pkgs/tools/aos/_abilities/package-profile-convergence.nix
      {
        options.aos.boot.preparationExecutable = lib.mkOption {
          type = lib.types.str;
          default = "${program.outPath}/bin/aos-boot-preparations";
        };
        options.aos.packageRuntime.configurationEvaluation.nixStoreExecutable = lib.mkOption {
          type = lib.types.str;
          default = "${program.outPath}/bin/nix-store";
        };
        config = {
          aos.config.unitGraph.enable = true;
          aos.packageRuntime.packageProfile.enable = true;
          aos.abilities.filesystem.operations.allocate.effects.aos-runtime-run-apm.input.path = "/run/apm";
          aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
        };
      }
    ];
  };
  input = evaluation.config.aos.abilities.serviceManagement.operations.realize.effects."control-plane.aos-activate".input;
  projectedEvaluation = evaluation.extendModules {
    modules = [
      {
        aos.services."control-plane.aos-activate" = {
          bootstrap = true;
          activationOwner = lib.mkForce "ability";
        };
      }
    ];
  };
  projectedInput = projectedEvaluation.config.aos.abilities.serviceManagement.operations.realize.effects."control-plane.aos-activate".input;
  specification = evaluation.config.aos.abilities.configuration.operations.file.effects.package-profile-specification;
  convergenceInput = evaluation.config.aos.abilities.serviceManagement.operations.realize.effects."package-profile-convergence.package-profile-convergence".input;
  # Resolve the one declared file output as the native dispatcher would before
  # invoking the handler; the typed input below still checks its dependency.
  convergenceRenderInput =
    convergenceInput
    // {
      lifecycle =
        convergenceInput.lifecycle
        // {
          start = map (command:
            command
            // {
              executable =
                command.executable
                // {
                  arguments = map (argument:
                    if argument == specification.outputs.path
                    then specification.input.path
                    else argument)
                  command.executable.arguments;
                };
            })
          convergenceInput.lifecycle.start;
        };
    };
in {
  inherit input projectedInput convergenceInput convergenceRenderInput;
  checks = {
    bootstrapProjectionIsOperationInput = projectedInput.bootstrap && !input.bootstrap;

    activatorRetainsHostNamespace =
      input.isolation.temporary_directory
      == "shared"
      && input.isolation.filesystem == "host"
      && input.isolation.home_access == "host"
      && input.isolation.host_paths == [];
    activatorRetainsHostAuthority = input.isolation.privilege == "privileged";
    convergenceRetainsHostNamespace =
      convergenceInput.isolation.temporary_directory
      == "shared"
      && convergenceInput.isolation.filesystem == "host"
      && convergenceInput.isolation.home_access == "host"
      && convergenceInput.isolation.host_paths == [];
    convergenceRetainsHostAuthority =
      convergenceInput.isolation.privilege
      == "privileged"
      && convergenceInput.policy.hardening == null;
    convergenceRetainsBootOrdering =
      convergenceInput.dependencies.after
      == ["aos-activate.service" "aos-registry-sync.service"]
      && convergenceInput.dependencies.requires == ["aos-activate.service" "aos-registry-sync.service"]
      && convergenceInput.activation_owner == "manager";
    convergenceInvokesNativeInstaller =
      (builtins.head convergenceInput.lifecycle.start).executable.arguments
      == ["install" "--system" "--from" specification.outputs.path "--yes"];
  };
}
