##! Checks the kmod-owned kernel-module provider through the standard fixed point.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kernelModules = serviceManagement.interfaces.kernelModules;
  request = serviceManagement.forProducer {
    consumerInstance = "workload";
    key = "required-modules";
    interface = kernelModules;
    parameters = {
      modules = ["zeta" "overlay"];
      required = true;
    };
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "kernel-modules";
            stage = "host";
          };
          bindings."test:kernel-modules" = {
            request = "consumer:required-modules";
            implementation = "kmod:kernel-modules";
            providerInstance = "kmod:manager";
            slot = "required-modules";
          };
        };
      }
    ];
    packageModules = [
      {
        name = "kmod";
        module.imports = [
          ../../pkgs/system/_kmod-abilities.nix
          ../../pkgs/system/_kmod-provider.nix
          {config.aos.abilities.instances.manager = {};}
        ];
      }
      {
        name = "consumer";
        module.imports = [
          {config.aos.abilities.instances.workload = {};}
          {config.aos.abilities = request;}
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  output = abilities.compositionOutputs."consumer:required-modules".readiness-resource;
in
  assert abilities.interfaces.${kernelModules.alias} == kernelModules.declaration;
  assert !(abilities.interfaces ? "kmod:kernel-modules");
  assert builtins.attrNames abilities.implementations == ["kmod:kernel-modules"];
  assert desired.kind == kernelModules.identity.name;
  assert desired.lifetime == "instance";
  assert desired.value == {
    modules = ["overlay" "zeta"];
    required = true;
  };
  assert desired.realization == {
    schema = "aos.kmod.module-set-realization/v1";
    modules = ["overlay" "zeta"];
    required = true;
  };
  assert output.value.resource == desired.resource;
  assert output.value.operations == ["observe"];
  assert output.phase == "planning";
  assert output.lifetime == "instance";
  true
