##! Verifies the package-owned boot-preparation implementation through the fixed point.
{
  lib,
  pkgs,
}: let
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-boot-preparation-provider;
    implementation = "boot-preparation";
  };
  preparation = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  childRequest = lib.abilities.compositionRequestKey {
    implementation = "aos-boot-preparation-provider:boot-preparation";
    providerInstance = "aos-boot-preparation-provider:manager";
    key = "prepare";
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules =
      ([
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "boot-preparation-provider";
            stage = "initrd";
          };
          instances."aos-boot-preparation-provider:manager" = {};
          bindings."test:prepare" = {
            request = "consumer:prepare";
            implementation = "aos-boot-preparation-provider:boot-preparation";
            providerInstance = "aos-boot-preparation-provider:manager";
            slot = "prepare";
          };
          bindings."test:prepare-command" = {
            request = childRequest;
            implementation = "aos-boot-preparation-provider:boot-preparation-command";
            providerInstance = "aos-boot-preparation-provider:manager";
            slot = "prepare";
          };
        };
      }
    ])
      ++ builtins.map lib.authenticatedModule (([
      {
        name = "aos-boot-preparation-provider";
        inherit (pkgs.aos-boot-preparation-provider) version;
        module = pkgs.aos-boot-preparation-provider.module + "/module.nix";
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
    ]) ++ ([selectedProvider]));


  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  output = abilities.compositionOutputs."consumer:prepare".preparation-resource;
  controller = abilities.implementations."aos-boot-preparation-provider:boot-preparation";
  terminal = abilities.implementations."aos-boot-preparation-provider:boot-preparation-command";
in
  assert builtins.attrNames abilities.implementations
  == [
    "aos-boot-preparation-provider:boot-preparation"
    "aos-boot-preparation-provider:boot-preparation-command"
  ];
  assert controller.providerModule != null;
  assert controller.handlerDescriptor == null;
  assert terminal.providerModule == null;
  assert terminal.handlerDescriptor != null;
  assert terminal.handlerDescriptor.entryPoint == "bin/aos-boot-preparation-provider";
  assert abilities.compositionPendingRequests == {};
  assert desired.kind == "aos.boot.preparation";
  assert desired.lifetime == "transaction";
  assert desired.realization == {schema = "aos.boot.preparation-realization/v1";};
  assert output.phase == "planning";
  assert output.lifetime == "transaction";
  assert output.value.resource == desired.resource; true
