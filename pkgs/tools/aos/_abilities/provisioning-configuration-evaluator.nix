##! Package-owned evaluation of retained authorized provisioning input.
{
  config,
  lib,
  packageName,
  ...
}: let
  types = lib.abilities.types;
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  alias = "storage-provisioning-configuration-evaluator";
  artifact = lib.abilities.packageOutput {output = "packageRuntime";};
  registrySnapshot =
    config.aos.abilities.interfaces."${packageName}:synchronized-registry-snapshot".methods.observe.outputs.registry-snapshot.schema;
  authorizedInputSource = types.taggedUnion {
    tag = "kind";
    variants.retained-artifact = types.record {
      fields = {
        kind = types.enum ["retained-artifact"];
        artifact = types.deferredResult types.artifactReference;
        content_sha256 = types.deferredResult types.digest;
      };
    };
  };
  parameters = types.record {
    fields = {
      request = storage.requestType;
      authorized_input = authorizedInputSource;
      registry_snapshot = types.deferredResult registrySnapshot;
    };
  };
  result = types.record {
    fields = {
      schema = types.enum ["aos.configuration.provisioning-evaluation-result/v1"];
      controller = types.resourceReference;
      handoff = types.resourceReference;
      manifest_blob = types.transactionBlobReference;
      manifest_sha256 = types.digest;
      registry_snapshot_sha256 = types.digest;
      host_module_sha256 = types.optional types.digest;
      instance_facts_sha256 = types.digest;
    };
  };
  evidence = types.record {
    fields = {
      schema = types.enum ["aos.configuration.provisioning-evaluation-observation/v1"];
      manifest_sha256 = types.optional types.digest;
      state = types.enum ["ready" "evaluated"];
    };
  };
  method = {
    description = "Evaluates retained authorized provisioning input against one synchronized registry snapshot.";
    inherit parameters;
    semantics = {
      requiredTargetAccess = "exclusive-write";
      stopsProvider = false;
    };
    targetResource = storage.identity.name;
    permittedOperations = ["evaluate"];
    guarantees = [];
    outputs.configuration-result = {
      schema = result;
      description = "Returns the graph-bound manifest blob identity and exact evaluation authorities.";
      phase = "runtime";
      lifetime = "transaction";
      visibility = "protected";
    };
    outcome = {
      completionEvidence = evidence;
      observationEvidence = evidence;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  declaration = lib.abilities.declareInterface {
    name = "aos.configuration.storage-provisioning-evaluation";
    description = "Evaluates retained authorized provisioning input into a canonical configuration manifest blob.";
    abi = 1;
    requestType = storage.requestType;
    methods.evaluate = method;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
    guarantees = [];
  };
in {
  config.aos.abilities = {
    interfaces.${alias} = declaration;

    implementations.${alias} = {
      description = "Evaluates retained provisioning input through the package-owned configuration runtime.";
      inherit artifact;
      interface = lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration declaration
      );
      methods = ["evaluate"];
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "libexec/aos-provisioning-configuration-evaluator";
        arguments = parameters;
        result = evidence;
      };
      providerModule = null;
      desiredType = null;
      requiredFeatures = [];
    };

    instances = lib.mkIf (config.aos.abilities.environment != null) {
      ${alias}.implementation = alias;
    };
  };
}
