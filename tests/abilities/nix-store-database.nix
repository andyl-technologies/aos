##! Checks the store-database provider package through the standard fixed point.
{lib}: let
  consumer = {config, ...}: let
    serviceManagement = lib.abilities.interfaces.serviceManagement;
  in {
    config.aos.abilities = lib.mkMerge [
      {instances.database-consumer = {};}
      (serviceManagement.forProducer {
        consumerInstance = "database-consumer";
        key = "database";
        interface = {
          alias = "nix-store-database";
          declaration = config.aos.abilities.interfaces."aos-nix-store-provider:nix-store-database";
        };
        parameters = {
          scope = "local";
          registration = {
            path = "/aos-registration";
            required = false;
          };
          prerequisites = [];
        };
      })
    ];
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "nix-store-database";
            stage = "host";
          };
          bindings."test:nix-store-database" = {
            request = "consumer:database";
            implementation = "aos-nix-store-provider:nix-store-database";
            providerInstance = "aos-nix-store-provider:manager";
            slot = "database";
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-nix-store-provider";
        module.imports = [
          ../../pkgs/tools/_aos-nix-store-provider-module.nix
          ../../pkgs/tools/_nix-store-provider.nix
          {config.aos.abilities.instances.manager = {};}
        ];
      }
      {
        name = "consumer";
        module = consumer;
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  readiness = abilities.compositionOutputs."consumer:database".readiness-resource;
in
  assert abilities.interfaces ? "aos-nix-store-provider:nix-store-database";
  assert builtins.attrNames abilities.implementations == ["aos-nix-store-provider:nix-store-database"];
  assert desired.kind == "aos.nix.store-database";
  assert desired.lifetime == "instance";
  assert desired.value
  == {
    scope = "local";
    registration = {
      path = "/aos-registration";
      required = false;
    };
    prerequisites = [];
  };
  assert desired.realization
  == {
    schema = "aos.nix.store-database-realization/v1";
    nix_store = {
      artifact = lib.abilities.packageOutput {package = "nix";};
      entry_point = "bin/nix-store";
      arguments = [];
    };
  };
  assert readiness.value.resource == desired.resource;
  assert readiness.value.operations == ["observe"];
  assert readiness.phase == "planning";
  assert readiness.lifetime == "instance"; true
