##! Projects the actual host activator for namespace and rendered-unit checks.
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
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/system/_service-management/module.nix
      ../../pkgs/tools/aos/_abilities/control-plane/module.nix
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
          aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
        };
      }
    ];
  };
  input = evaluation.config.aos.abilities.serviceManagement.operations.realize.effects."control-plane.aos-activate".input;
in {
  inherit input;
  checks = {
    activatorRetainsHostNamespace =
      input.isolation.temporary_directory
      == "shared"
      && input.isolation.filesystem == "host"
      && input.isolation.home_access == "host"
      && input.isolation.host_paths == [];
    activatorRetainsHostAuthority = input.isolation.privilege == "privileged";
  };
}
