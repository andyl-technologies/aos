##! Verifies the package-owned boot-preparation implementation through the fixed point.
{lib}: let
  preparation = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "boot-preparation-provider";
            stage = "initrd";
          };
          bindings."test:prepare" = {
            request = "consumer:prepare";
            implementation = "aos-boot-preparation-provider:boot-preparation";
            providerInstance = "aos-boot-preparation-provider:manager";
            slot = "prepare";
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-boot-preparation-provider";
        module.imports = [
          ../../pkgs/boot/_aos-boot-preparation-provider/module.nix
          ../../pkgs/boot/_aos-boot-preparation-provider/provider.nix
          {config.aos.abilities.instances.manager = {};}
        ];
      }
      {
        name = "consumer";
        module.config.aos.abilities = lib.mkMerge [
          {instances.workload = {};}
          (serviceManagement.forProducer {
            consumerInstance = "workload";
            key = "prepare";
            interface = preparation;
            methods = ["observe" "prepare"];
            parameters = {
              execution = {
                artifact = lib.abilities.packageOutput {};
                entry_point = "libexec/prepare";
                arguments = [];
              };
              prerequisites = [];
            };
          })
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  output = abilities.compositionOutputs."consumer:prepare".preparation-resource;
in
  assert builtins.attrNames abilities.implementations == ["aos-boot-preparation-provider:boot-preparation"];
  assert desired.kind == "aos.boot.preparation";
  assert desired.lifetime == "transaction";
  assert desired.realization == {schema = "aos.boot.preparation-realization/v1";};
  assert output.phase == "planning";
  assert output.lifetime == "transaction";
  assert output.value.resource == desired.resource;
  true
