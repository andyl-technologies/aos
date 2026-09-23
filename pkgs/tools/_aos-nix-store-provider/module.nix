##! Package-owned Nix store database and runtime integration declarations.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  ...
}: let
  inherit (lib.abilities) declareInterface interfaceDocumentFromDeclaration interfaceIdentity types;

  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceInterfaces = serviceManagement.interfaces;
  serviceTypes = serviceManagement.types;
  contentObject = lib.abilities.interfaces.contentAddressedArtifacts;
  contentObjectOperations = contentObject.operationInterface;

  storeDatabase = lib.abilities.interfaces.nixStoreDatabase.interface;
  inherit (storeDatabase) declaration identity requestType observationType realizationType lifecycle aggregation;
  methods = storeDatabase.methodDeclarations;
  interfaceName = identity.name;
  interfaceAlias = storeDatabase.alias;
  effectsName = "aos.nix.store-database-effects";
  effectsAlias = "nix-store-database-effects";
  providerArtifact = lib.abilities.packageOutput {};
  runtimeConsumer = "runtime";
  resultOf = lib.abilities.resultOf;

  coreutilsSelector = lib.abilities.packageOutput {package = "coreutils";};
  grepSelector = lib.abilities.packageOutput {package = "grep";};
  nixSelector = lib.abilities.packageOutput {package = "nix";};
  coreutilsArtifact = packageArtifactFor coreutilsSelector;
  grepArtifact = packageArtifactFor grepSelector;
  nixArtifact = packageArtifactFor nixSelector;

  configurationRequest = "nix-configuration";
  configurationEntryRequest = "nix-configuration-entry";
  profileStorageRequest = "profile-storage";
  gcRootDirectoryRequest = "gcroot-directory";
  gcRootMountRequest = "gcroot-mount";

  effectsDeclaration = declareInterface {
    name = effectsName;
    description = "Executes admitted Nix store database operations for one exact controller-owned resource.";
    abi = 1;
    inherit requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = interfaceIdentity (interfaceDocumentFromDeclaration effectsDeclaration);
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = runtimeConsumer;
      inherit key interface parameters;
    };
  runtimeConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = runtimeConsumer;
    declaration = {
      name = configurationRequest;
      source = {
        kind = "inline-text";
        content = ''
          # Managed by the selected AOS package-store provider.
          build-users-group =
        '';
      };
      mode = "0444";
    };
  };
  configurationEntry = producer configurationEntryRequest serviceInterfaces.filesystemEntry {
    name = configurationEntryRequest;
    entry = {
      kind = "copied-file";
      source = {
        kind = "execution-path";
        resource = resultOf configurationRequest "resource";
        path = resultOf configurationRequest "planned-path";
      };
      maximum_size_bytes = types.limits.maxStringLength;
    };
    destination = "/etc/nix/nix.conf";
    owner = "root";
    group = "root";
    mode = "0444";
    prerequisites = [(resultOf configurationRequest "resource")];
  };
  profileStorage = producer profileStorageRequest serviceInterfaces.persistentStorageAllocation {
    name = "aos-profiles";
    purpose = "state";
    mode = "0755";
    requested_path = "/var/lib/profiles";
    owner = "root";
    group = "root";
  };
  gcRootDirectory = producer gcRootDirectoryRequest serviceInterfaces.filesystemEntry {
    name = "aos-profile-gcroots";
    entry.kind = "directory";
    destination = "/nix/var/nix/gcroots/aos-profiles";
    owner = "root";
    group = "root";
    mode = "0755";
    prerequisites = [];
  };
  gcRootMount = producer gcRootMountRequest serviceInterfaces.mountResource {
    name = "aos-profile-gcroots";
    enabled = true;
    source = resultOf profileStorageRequest "planned-path";
    destination = resultOf gcRootDirectoryRequest "planned-path";
    options = ["bind"];
  };
  runtimeProducers = [
    runtimeConfiguration
    configurationEntry
    profileStorage
    gcRootDirectory
    gcRootMount
  ];
  runtimeSelected =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host"
    && abilitySelection != null
    && abilitySelection.isImplementationSelected interfaceAlias;
in {
  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge [
        {
          interfaces = {
            ${interfaceAlias} = declaration;
            ${effectsAlias} = effectsDeclaration;
          };

          implementations.${interfaceAlias} = {
            description = "Converges a local Nix store database through the checked package-owned controller.";
            interface = interfaceAlias;
            artifact = providerArtifact;
            artifacts = [coreutilsSelector grepSelector nixSelector];
            methods = builtins.attrNames methods;
            guarantees = [];
            requirements.effects = {
              alias = "effects";
              description = "Invokes the package-owned terminal Nix store database handler.";
              accepted_interfaces = [effectsIdentity];
              methods = builtins.attrNames methods;
              guarantees = [];
              strength = "required";
              fallback = null;
            };
            providerModule = {
              artifact = lib.abilities.packageOutput {output = "module";};
              path = "provider.nix";
            };
            desiredType = realizationType;
            requiredFeatures = [];
          };

          implementations.${effectsAlias} = {
            description = "Executes authorized Nix store database operations through the package-owned handler.";
            interface = effectsAlias;
            artifact = providerArtifact;
            methods = builtins.attrNames methods;
            guarantees = [];
            handlerDescriptor = {
              artifact = providerArtifact;
              entryPoint = "libexec/aos-nix-store-provider";
              arguments = requestType;
              result = observationType;
            };
            desiredType = null;
            requiredFeatures = [];
          };

          implementations.content-addressed-object = {
            description = "Owns persistent content-addressed objects committed through the checked Nix-store effects interface.";
            interface = contentObject.identity;
            artifact = providerArtifact;
            methods = contentObject.methods;
            guarantees = [];
            requirements.effects = {
              alias = "effects";
              description = "Invokes the package-owned terminal content-object handler.";
              accepted_interfaces = [contentObjectOperations.identity];
              methods = contentObject.methods;
              guarantees = [];
              strength = "required";
              fallback = null;
            };
            providerModule = {
              artifact = lib.abilities.packageOutput {output = "module";};
              path = "content-object-provider.nix";
            };
            desiredType = contentObject.realizationType;
            requiredFeatures = [];
          };

          implementations.${contentObjectOperations.alias} = {
            description = "Executes authorized content-object operations through the package-owned Nix-store handler.";
            interface = contentObjectOperations.identity;
            artifact = providerArtifact;
            methods = contentObject.methods;
            guarantees = [];
            handlerDescriptor = {
              artifact = providerArtifact;
              entryPoint = "libexec/aos-nix-store-provider";
              arguments = contentObject.methodParameters;
              result = contentObject.observationType;
            };
            desiredType = null;
            requiredFeatures = [];
          };

          requirementTemplates.${interfaceAlias} = {
            description = "Requires convergence and observation of the local Nix store database.";
            inherit (identity) abi descriptor;
            interface = identity.name;
            methods = builtins.attrNames methods;
            guarantees = [];
            strength = "required";
            fallback = null;
          };
        }
        (lib.mkIf runtimeSelected {
          runtimeChecks.nix-store = {
            description = "Selected package-store readiness and retention checks";
            checks = [
              {
                name = "database-ready";
                description = "the selected package store initialized its local database";
                script = ''
                  vm.succeed("${coreutilsArtifact}/bin/test -f /nix/var/nix/db/db.sqlite")
                '';
              }
              {
                name = "managed-config";
                description = "the selected package store installed its single-user configuration";
                script = ''
                  vm.succeed("${grepArtifact}/bin/grep -Fx 'build-users-group =' /etc/nix/nix.conf")
                '';
              }
              {
                name = "gcroot-bridge";
                description = "durable AOS profiles are retained by the selected package store";
                script = ''
                  vm.succeed(
                      "${coreutilsArtifact}/bin/test "
                      "$( ${coreutilsArtifact}/bin/stat -c %d:%i /var/lib/profiles) = "
                      "$( ${coreutilsArtifact}/bin/stat -c %d:%i /nix/var/nix/gcroots/aos-profiles)"
                  )
                '';
              }
              {
                name = "current-system-valid";
                description = "the selected package store recognizes the booted system closure";
                script = ''
                  vm.succeed(
                      "${nixArtifact}/bin/nix-store --check-validity "
                      "$( ${coreutilsArtifact}/bin/readlink /run/current-system)"
                  )
                '';
              }
            ];
          };
        })
      ];
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = runtimeProducers;
      enabled = runtimeSelected;
    })
  ];
}
