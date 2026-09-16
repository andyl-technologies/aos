##! Native provider declaration for typed configuration materialization.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interface = serviceManagement.interfaces.managedConfiguration;
  imagePlatform = lib.abilities.interfaces.imageRolloutPlatform;
  imagePlatformInterfaces = imagePlatform.interfaces;
  abilityTypes = lib.abilities.types;
  runtimeArtifact = lib.abilities.packageOutput {output = "packageRuntime";};
  realizationType = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.configuration.materializer-realization/v1"];
      path = serviceManagement.types.executionPath;
    };
  };
  terminalMethods = declaration:
    builtins.mapAttrs
    (_: method:
      method
      // {
        description = "Executes one checked lower-level ${declaration.name} operation.";
      })
    declaration.methods;
  configurationTerminalDeclaration = lib.abilities.declareInterface {
    name = "aos.configuration.materialization-terminal";
    description = "Executes configuration effects selected by a pure materialization controller.";
    abi = 1;
    requestType = interface.requestType;
    outputs = {};
    methods = terminalMethods interface.declaration;
    inherit (interface.declaration) lifecycle aggregation;
    guarantees = [];
  };
  configurationTerminalDocument =
    lib.abilities.interfaceDocumentFromDeclaration configurationTerminalDeclaration;
  configurationTerminalIdentity =
    lib.abilities.interfaceIdentity configurationTerminalDocument;
  rolloutRequest = imagePlatform.rolloutRequest;
  rolloutDeclaration = imagePlatformInterfaces.rollout.declaration;
  rolloutMethods = rolloutDeclaration.methods;
  rolloutObservation = imagePlatformInterfaces.rollout.observationType;
  rolloutRealizationType = abilityTypes.record {
    fields.schema = abilityTypes.enum ["aos.image-rollout.realization/v1"];
  };
  rolloutTerminalDeclaration = lib.abilities.declareInterface {
    name = "aos.apm.ab-image-rollout-terminal";
    description = "Executes A/B image effects selected by the pure rollout controller.";
    abi = 1;
    requestType = rolloutRequest;
    outputs = {};
    methods = builtins.mapAttrs (name: method:
      method
      // {
        description = "Executes one checked package-owned rollout-state operation.";
        parameters = abilityTypes.record {
          fields =
            {rollout = rolloutRequest;}
            // lib.optionalAttrs (name == "retain" || name == "retire") {
              platform = imagePlatformInterfaces.artifactStorage.observationType;
            }
            // lib.optionalAttrs (name == "select") {
              entry = abilityTypes.deferredResult abilityTypes.runtimeString;
            }
            // lib.optionalAttrs (name == "observe-health") {
              health = abilityTypes.optional (
                abilityTypes.deferredResult imagePlatformInterfaces.healthObservation.observationType
              );
            };
        };
      })
    rolloutMethods;
    inherit (rolloutDeclaration) lifecycle aggregation;
    guarantees = [];
  };
  rolloutTerminalDocument =
    lib.abilities.interfaceDocumentFromDeclaration rolloutTerminalDeclaration;
  rolloutTerminalIdentity = lib.abilities.interfaceIdentity rolloutTerminalDocument;
  terminalRequirement = alias: description: identity: methods: {
    inherit alias description methods;
    accepted_interfaces = [identity];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  qualificationObserver = entryPoint:
    lib.qualification.abilityObserver {
      artifact = runtimeArtifact;
      inherit entryPoint;
    };
  conformanceFamilies = [
    "authority-revocation"
    "dependent-effect"
    "durability-recovery"
    "foreign-resource"
    "incarnation-replacement"
    "provider-state-transfer"
  ];
  rolloutConformanceFamilies = ["rollout-durability"];
in {
  config.aos.abilities = {
    interfaces.configuration-materialization-terminal = configurationTerminalDeclaration;
    interfaces.image-rollout-terminal = rolloutTerminalDeclaration;
    implementations.configuration-materialization = {
      description = "Materializes typed configuration through the AOS configuration provider.";
      interface = "configuration-materialization";
      artifact = runtimeArtifact;
      inherit (interface) methods;
      guarantees = [];
      requirements.terminal =
        terminalRequirement
        "terminal"
        "Selects the exact package-owned configuration effect handler."
        configurationTerminalIdentity
        interface.methods;
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "configuration-provider/provider.nix";
      };
      desiredType = realizationType;
      requiredFeatures = [];
      qualification = {
        adapter = "configuration-materialization";
        observationKind = "filesystem";
        scope = "host-resource";
        inherit conformanceFamilies;
        observer = qualificationObserver "libexec/aos-configuration-observer";
      };
    };
    implementations.configuration-materialization-terminal = {
      description = "Executes checked configuration effects for the pure materialization controller.";
      interface = "configuration-materialization-terminal";
      artifact = runtimeArtifact;
      methods = interface.methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = runtimeArtifact;
        entryPoint = "libexec/aos-configuration-provider";
        arguments = interface.requestType;
        result = interface.observationType;
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };
    implementations.image-rollout-effects = {
      description = "Executes A/B image transitions through the AOS package-owned rollout handler.";
      interface = imagePlatformInterfaces.rollout.alias;
      artifact = runtimeArtifact;
      methods = builtins.attrNames rolloutMethods;
      guarantees = [];
      requirements = {
        terminal =
          terminalRequirement
          "terminal"
          "Selects the exact package-owned A/B image state handler."
          rolloutTerminalIdentity
          (builtins.attrNames rolloutMethods);
        artifact-storage =
          terminalRequirement
          "artifact-storage"
          "Retains immutable boot payloads through the selected boot storage provider."
          imagePlatformInterfaces.artifactStorage.identity
          imagePlatformInterfaces.artifactStorage.methods;
        boot-selection =
          terminalRequirement
          "boot-selection"
          "Resolves and selects entries through the selected boot provider."
          imagePlatformInterfaces.selection.identity
          imagePlatformInterfaces.selection.methods;
        boot-success =
          terminalRequirement
          "boot-success"
          "Publishes running-boot success through the selected boot provider."
          imagePlatformInterfaces.success.identity
          imagePlatformInterfaces.success.methods;
        health-observation =
          terminalRequirement
          "health-observation"
          "Observes candidate health through the selected image provider."
          imagePlatformInterfaces.healthObservation.identity
          imagePlatformInterfaces.healthObservation.methods;
        host-restart =
          terminalRequirement
          "host-restart"
          "Requests image-transition restarts through the selected host provider."
          imagePlatformInterfaces.hostRestart.identity
          imagePlatformInterfaces.hostRestart.methods;
      };
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "configuration-provider/provider.nix";
      };
      desiredType = rolloutRealizationType;
      requiredFeatures = [];
      qualification = {
        adapter = "image-rollout";
        observationKind = "rollout";
        scope = "host-machine";
        conformanceFamilies = rolloutConformanceFamilies;
        observer = qualificationObserver "libexec/aos-image-rollout-observer";
      };
    };
    implementations.image-rollout-terminal = {
      description = "Executes checked A/B image effects for the pure rollout controller.";
      interface = "image-rollout-terminal";
      artifact = runtimeArtifact;
      methods = builtins.attrNames rolloutMethods;
      guarantees = [];
      handlerDescriptor = {
        artifact = runtimeArtifact;
        entryPoint = "libexec/aos-image-rollout-provider";
        arguments = rolloutRequest;
        result = rolloutObservation;
      };
      desiredType = rolloutRealizationType;
      requiredFeatures = [];
    };

    instances = lib.mkIf (config.aos.abilities.environment != null) {
      configuration-materialization.implementation = "configuration-materialization";
      configuration-materialization-terminal.implementation = "configuration-materialization-terminal";
      image-rollout-effects.implementation = "image-rollout-effects";
      image-rollout-terminal.implementation = "image-rollout-terminal";
    };
  };
}
