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

  interfaceName = "aos.nix.store-database";
  interfaceAlias = "nix-store-database";
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

  registrationInput = types.record {
    fields = {
      path = types.executionPath;
      required = types.boolean;
    };
  };
  requestType = types.record {
    fields = {
      scope = types.enum ["local"];
      registration = types.optional registrationInput;
      prerequisites = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.nix-store-database-observation/v1"];
      expected = requestType;
      initialized = types.boolean;
      registration_digest = types.optional types.digest;
      registration_state = types.enum ["absent" "loaded" "not-requested" "partial" "unknown"];
      state = types.enum ["absent" "degraded" "ready" "unknown"];
    };
  };
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.nix.store-database-realization/v1"];
      nix_store = types.executableReference;
    };
  };
  lifecycle = {
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = "nix-store-database";
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  observationOutput = phase:
    output phase "attempt"
    "Reports the exact observed local Nix store database state."
    observationType;
  retainedResourceOutput =
    output "runtime" "persistent"
    "References the exact converged Nix store database retained across provider instances."
    types.resourceReference;
  method = name: description: access: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      stopsProvider = false;
    };
    parameters = requestType;
    targetResource = interfaceName;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  methods = {
    converge =
      method
      "converge"
      "Initializes the local Nix store database and imports the exact admitted registration stream."
      "exclusive-write"
      {
        observation = observationOutput "runtime";
        retained-resource = retainedResourceOutput;
      };
    observe =
      method
      "observe"
      "Observes whether the local Nix store database contains the exact admitted registration stream."
      "read"
      {observation = observationOutput "observation";};
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Converges and observes one local Nix store database from an image registration stream.";
    abi = 1;
    inherit requestType methods lifecycle aggregation;
    outputs.readiness-resource =
      output "planning" "persistent"
      "References readiness for the exact requested Nix store database revision."
      types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
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
        resource = resultOf configurationRequest "retained-resource";
        path = resultOf configurationRequest "planned-path";
      };
      maximum_size_bytes = types.limits.maxStringLength;
    };
    destination = "/etc/nix/nix.conf";
    owner = "root";
    group = "root";
    mode = "0444";
    prerequisites = [(resultOf configurationRequest "retained-resource")];
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
  runtimeContributions = builtins.map serviceManagement.splitContribution [
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
  config = {
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
            artifact = providerArtifact;
            path = "share/aos/providers/nix-store-database.nix";
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
            artifact = providerArtifact;
            path = "share/aos/providers/content-addressed-object.nix";
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
      (lib.mkMerge (builtins.map (contribution: contribution.declarations) runtimeContributions))
      (lib.mkIf runtimeSelected
        (lib.mkMerge (
          [{instances.${runtimeConsumer} = {};}]
          ++ builtins.map (contribution: contribution.configured) runtimeContributions
        )))
    ];

    aos.contributions.runtimeChecks = lib.mkIf runtimeSelected {
      nix-store = {
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
    };
  };
}
