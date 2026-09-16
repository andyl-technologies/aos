##! Package-owned complete initrd configuration evaluation.
{
  config,
  lib,
  ...
}: let
  types = lib.abilities.types;
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  alias = "storage-provisioning-configuration-evaluator";
  artifact = lib.abilities.packageOutput {output = "packageRuntime";};
  authorizedInput = lib.abilities.interfaces.configurationInput.types.authorizedInput;
  storeView = lib.abilities.interfaces.packageStoreReadView.interfaces.readView;
  marker = lib.abilities.interfaces.blockStorage.types.provisioningMarkerObservation;
  authorizedInputSource = types.taggedUnion {
    tag = "kind";
    variants = {
      direct-result = types.record {
        fields = {
          kind = types.enum ["direct-result"];
          input = types.deferredResult authorizedInput;
        };
      };
      retained-artifact = types.record {
        fields = {
          kind = types.enum ["retained-artifact"];
          artifact = types.deferredResult types.artifactReference;
          content_sha256 = types.deferredResult types.digest;
        };
      };
    };
  };
  parameters = types.record {
    fields = {
      request = storage.requestType;
      authorized_input = authorizedInputSource;
      marker = types.deferredResult marker;
      store_view = types.deferredResult storeView.locatorType;
    };
  };
  result = types.record {
    fields = {
      schema = types.enum ["aos.configuration.provisioning-evaluation-result/v1"];
      manifest_blob = types.transactionBlobReference;
      manifest_sha256 = types.digest;
      provisioning_plan_sha256 = types.digest;
      static_contract = types.executionPath;
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
    description = "Evaluates authorized provisioning input through the complete initrd configuration fixed point.";
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
      description = "Returns the canonical manifest blob identity and exact initrd evaluation authority.";
      phase = "runtime";
      lifetime = "transaction";
      visibility = "protected";
    };
    outputs.provisioning-plan = {
      schema = lib.abilities.interfaces.blockStorage.types.provisioningPlan;
      description = "Returns the canonical storage plan projected from the same complete fixed point.";
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
    description = "Evaluates authorized input into one canonical initrd manifest and storage-plan projection.";
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
      description = "Evaluates provisioning input through the package-owned complete initrd configuration runtime.";
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
