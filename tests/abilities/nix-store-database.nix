##! Checks the store-database provider package through the standard fixed point.
{
  lib,
  pkgs,
}: let
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-nix-store-provider;
    implementation = "nix-store-database";
  };
  childRequestKey = lib.abilities.compositionRequestKey {
    implementation = "aos-nix-store-provider:nix-store-database";
    providerInstance = "aos-nix-store-provider:manager";
    key = "database";
  };
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
    enableAbilitySelection = true;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "nix-store-database";
            stage = "initrd";
          };
          instances."aos-nix-store-provider:manager" = {};
          bindings."test:nix-store-database" = {
            request = "consumer:database";
            implementation = "aos-nix-store-provider:nix-store-database";
            providerInstance = "aos-nix-store-provider:manager";
            slot = "database";
          };
          bindings."test:nix-store-database-effects" = {
            request = childRequestKey;
            implementation = "aos-nix-store-provider:nix-store-database-effects";
            providerInstance = "aos-nix-store-provider:manager";
            slot = "database";
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-nix-store-provider";
        inherit (pkgs.aos-nix-store-provider) version;
        module = pkgs.aos-nix-store-provider.module + "/module.nix";
      }
      {
        name = "consumer";
        module = consumer;
      }
    ];
    selectedProviderModules = [selectedProvider];
  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (
    builtins.filter
    (resource: resource.kind == "aos.nix.store-database")
    (builtins.attrValues abilities.desiredResources)
  );
  readiness = abilities.compositionOutputs."consumer:database".readiness-resource;
  transition = abilities.implementations."aos-nix-store-provider:nix-store-database".transition;
  effectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration abilities.interfaces."aos-nix-store-provider:nix-store-database-effects"
  );
  effectsHandler = abilities.implementations."aos-nix-store-provider:nix-store-database-effects".handlerDescriptor;
  artifactController = abilities.implementations."aos-nix-store-provider:content-addressed-object";
  artifactHandler = abilities.implementations."aos-nix-store-provider:content-addressed-object-operations".handlerDescriptor;
  transitionMethods = kind: let
    active = builtins.elem kind ["create" "update" "reconcile-stopped" "reconcile-divergent"];
    binding = {
      id = "nix-store-database-effects";
      request.consumer = desired.resource.provider;
      interface = effectsInterface;
      caller_grant = {
        methods = ["converge" "observe"];
        resources = [
          {
            resource = desired.resource;
            access = "exclusive-write";
            operations = ["converge"];
          }
        ];
      };
    };
    fragment = transition {
      provider = desired.resource.provider;
      operation_scope = ["nix-store-database"];
      changes = [
        {
          inherit kind;
          resource = desired.resource;
          current = null;
          desired = null;
        }
      ];
      authorized_bindings = lib.optional active {
        authority.role = "desired";
        inherit binding;
      };
      controllers = lib.optional active {
        resource = desired.resource;
        controller = {
          provider = desired.resource.provider;
          group = "nix-store-database";
        };
      };
    };
  in
    builtins.map (operation: operation.method) fragment.operations;
in
  assert abilities.interfaces ? "aos-nix-store-provider:nix-store-database";
  assert abilities.interfaces ? "content-addressed-object";
  assert abilities.interfaces ? "content-addressed-object-operations";
  assert builtins.attrNames abilities.implementations
  == [
    "aos-nix-store-provider:content-addressed-object"
    "aos-nix-store-provider:content-addressed-object-operations"
    "aos-nix-store-provider:nix-store-database"
    "aos-nix-store-provider:nix-store-database-effects"
  ];
  assert abilities.compositionRequests.${childRequestKey}.parameters == desired.value;
  assert effectsHandler.entryPoint == "libexec/aos-nix-store-provider";
  assert artifactController.handlerDescriptor == null;
  assert artifactController.providerModule.path == "content-object-provider.nix";
  assert artifactHandler.entryPoint == "libexec/aos-nix-store-provider";
  assert desired.kind == "aos.nix.store-database";
  assert desired.lifetime == "persistent";
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
  assert readiness.lifetime == "persistent";
  assert transitionMethods "create" == ["converge"];
  assert transitionMethods "update" == ["converge"];
  assert transitionMethods "reconcile-stopped" == ["converge"];
  assert transitionMethods "reconcile-divergent" == ["converge"];
  assert transitionMethods "unchanged" == [];
  assert transitionMethods "remove" == []; true
