##! Native provider declaration for typed configuration materialization.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interface = serviceManagement.interfaces.managedConfiguration;
  abilityTypes = lib.abilities.types;
  runtimeArtifact = lib.abilities.packageOutput {output = "packageRuntime";};
  realizationType = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.configuration.materializer-realization/v1"];
      path = serviceManagement.types.executionPath;
    };
  };
  rolloutRequest = abilityTypes.record {
    fields = {
      candidate = imageIdentity;
      concurrency = abilityTypes.integer {
        minimum = 1;
        maximum = 1;
      };
      predecessor = imageIdentity;
      retention-expires-at-millis = abilityTypes.integer {
        minimum = 1;
        maximum = 9007199254740991;
      };
      strategy = abilityTypes.enum ["single-host-ab-v1"];
    };
  };
  imageIdentity = abilityTypes.record {
    fields = {
      executor = storePath;
      state-format = abilityTypes.string {
        maxLength = 128;
        syntax = null;
      };
      toplevel = storePath;
      uki = storePath;
    };
  };
  storePath = abilityTypes.string {
    maxLength = 4096;
    syntax = null;
  };
  rolloutObservation = abilityTypes.record {
    fields = {
      active-image = abilityTypes.enum ["candidate" "predecessor"];
      candidate-prepared = abilityTypes.boolean;
      drained = abilityTypes.boolean;
      healthy = abilityTypes.optional abilityTypes.boolean;
      lease-expires-at-millis = abilityTypes.optional (abilityTypes.integer {
        minimum = 1;
        maximum = 9007199254740991;
      });
      phase = abilityTypes.enum [
        "booted"
        "drained"
        "fallback-retained"
        "healthy-retained"
        "prepared"
        "retained"
        "retired"
        "selected"
      ];
      schema = abilityTypes.enum ["aos.ability.ab-image-rollout-observation/v1"];
    };
  };
  rolloutOutput = schema: {
    description = "Reports the checked state established by this rollout step.";
    inherit schema;
    phase = "observation";
    lifetime = "transaction";
    visibility = "protected";
  };
  rolloutMethod = name: {
    description = "Executes the ${name} step of a checked single-host A/B rollout.";
    semantics = {
      requiredTargetAccess = "exclusive-write";
      stopsProvider = false;
    };
    parameters = rolloutRequest;
    targetResource = "aos.ab-image-rollout-effects";
    outputs =
      {
        rollout-state = rolloutOutput rolloutObservation;
      }
      // lib.optionalAttrs (name == "observe-health") {
        healthy = rolloutOutput abilityTypes.boolean;
      };
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = rolloutObservation;
      observationEvidence = rolloutObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  rolloutMethods = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = rolloutMethod name;
    }) [
      "drain"
      "hold"
      "observe-boot"
      "observe-health"
      "prepare"
      "retain"
      "retire"
      "select"
      "withdraw"
    ]);
  rolloutDeclaration = lib.abilities.declareInterface {
    name = "aos.ab-image-rollout-effects";
    description = "Executes the physical steps of a checked single-host A/B image rollout.";
    abi = 1;
    requestType = rolloutRequest;
    outputs = {};
    methods = rolloutMethods;
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = false;
      retainsPersistentByDefault = true;
      persistentDeleteMethod = null;
    };
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "rollout-effects";
    };
  };
  rolloutRealizationType = abilityTypes.record {
    fields.schema = abilityTypes.enum ["aos.image-rollout.realization/v1"];
  };
in {
  config.aos.abilities = {
    interfaces.configuration-materialization = interface.declaration;
    interfaces.image-rollout-effects = rolloutDeclaration;
    implementations.configuration-materialization = {
      description = "Materializes typed configuration through the AOS configuration provider.";
      interface = "configuration-materialization";
      artifact = runtimeArtifact;
      inherit (interface) methods;
      guarantees = [];
      providerModule = {
        artifact = runtimeArtifact;
        path = "share/aos/providers/configuration-materialization.nix";
      };
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
      interface = "image-rollout-effects";
      artifact = runtimeArtifact;
      methods = builtins.attrNames rolloutMethods;
      guarantees = [];
      providerModule = {
        artifact = runtimeArtifact;
        path = "share/aos/providers/configuration-materialization.nix";
      };
      handlerDescriptor = {
        artifact = runtimeArtifact;
        entryPoint = "libexec/aos-image-rollout-provider";
        arguments = rolloutRequest;
        result = rolloutObservation;
      };
      desiredType = rolloutRealizationType;
      requiredFeatures = [];
    };
  };
}
