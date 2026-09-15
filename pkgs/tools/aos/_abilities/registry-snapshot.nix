##! Package-owned authenticated registry snapshot evidence.
{
  config,
  lib,
  ...
}: let
  types = lib.abilities.types;
  alias = "synchronized-registry-snapshot";
  name = "aos.registry.synchronized-snapshot";
  artifact = lib.abilities.packageOutput {output = "packageRuntime";};
  hostStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "host";
  canonicalResources = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 16;
    unique = true;
    canonicalOrder = true;
  };
  requestType = types.record {
    fields = {
      scope = types.enum ["system"];
      controller = types.deferredResult types.resourceReference;
      handoff = types.deferredResult types.resourceReference;
      synchronization = types.deferredResult types.resourceReference;
      prerequisites = canonicalResources;
    };
  };
  releaseIdentity = types.record {
    fields = {
      registry = types.string {
        maxLength = 128;
        syntax = "local-key-v1";
      };
      release_tag = types.string {
        maxLength = 128;
        syntax = null;
      };
      commit = types.string {
        maxLength = 64;
        syntax = null;
      };
      tag_signer_key = types.string {
        maxLength = 64;
        syntax = null;
      };
    };
  };
  snapshotType = types.record {
    fields = {
      schema = types.enum ["aos.registry.synchronized-snapshot/v1"];
      scope = types.enum ["system"];
      controller = types.resourceReference;
      handoff = types.resourceReference;
      synchronization = types.resourceReference;
      static_contract = types.artifactReference;
      releases = types.list {
        element = releaseIdentity;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      snapshot_sha256 = types.digest;
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.registry-snapshot-observation/v1"];
      expected = requestType;
      snapshot_sha256 = {
        type = types.optional types.digest;
        optional = true;
      };
      state = types.enum ["ready" "unavailable"];
    };
  };
  output = schema: description: {
    inherit schema description;
    phase = "runtime";
    lifetime = "transaction";
    visibility = "protected";
  };
  method = {
    description = "Authenticates the exact synchronized registry and immutable image package authorities.";
    parameters = requestType;
    targetResource = name;
    permittedOperations = ["observe"];
    guarantees = [];
    semantics = {
      requiredTargetAccess = "read";
      stopsProvider = false;
    };
    outputs = {
      observation = output observationType "Reports whether the synchronized snapshot is available.";
      registry-snapshot = output snapshotType "Returns the authenticated authority used for exact package-module resolution.";
    };
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  declaration = lib.abilities.declareInterface {
    inherit name requestType;
    description = "Authenticates one synchronized package registry snapshot without exposing its ambient cache paths.";
    abi = 1;
    methods.observe = method;
    outputs = {};
    lifecycle.persistentDeleteMethod = null;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
    guarantees = [];
  };
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
in {
  config.aos.abilities = {
    interfaces.${alias} = declaration;

    implementations.${alias} = {
      description = "Observes registry synchronization through the package runtime's authenticated resolver.";
      inherit artifact;
      interface = identity;
      methods = ["observe"];
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "libexec/aos-registry-snapshot-provider";
        arguments = requestType;
        result = observationType;
      };
      providerModule = null;
      desiredType = null;
      requiredFeatures = [];
    };

    instances = lib.mkIf hostStage {
      ${alias}.implementation = alias;
    };
  };
}
