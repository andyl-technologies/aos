##! Canonical provider-neutral kernel-tunable convergence interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let

  alias = "kernel-tunables";
  interfaceName = "aos.kernel.tunables";
  tunableValue = types.string {
    maxLength = 4096;
    syntax = null;
  };
  tunables = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 256;
    value = tunableValue;
  };
  dependencies = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 64;
    unique = true;
    canonicalOrder = true;
  };
  requestType = types.record {
    fields = {
      values = tunables;
      inherit dependencies;
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.kernel-tunables-observation/v1"];
      expected = requestType;
      observed = tunables;
      state = types.enum ["applied" "drifted" "unmanaged" "unknown"];
      discrepancies = types.list {
        element = types.localKey;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  realizationType = types.record {
    fields.schema = types.enum ["aos.kernel.tunables-realization/v1"];
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  observationOutput = phase:
    output phase "attempt" "Reports the exact observed kernel-tunable values." observationType;
  retainedResourceOutput =
    output "runtime" "instance" "References the exact converged kernel-tunable resource." types.resourceReference;
  method = name: description: access: stopsProvider: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
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
    apply = method "apply" "Converges the exact requested kernel-tunable map." "exclusive-write" false {
      observation = observationOutput "runtime";
      retained-resource = retainedResourceOutput;
    };
    observe = method "observe" "Observes the exact requested kernel-tunable map." "read" false {
      observation = observationOutput "observation";
    };
    remove = method "remove" "Restores values previously replaced by this resource." "exclusive-write" true {
      observation = observationOutput "runtime";
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
    controllerGroup = "kernel-tunables";
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Converges exact bounded kernel-tunable maps without exposing a manager backend.";
    abi = 1;
    inherit requestType methods lifecycle aggregation;
    outputs.readiness-resource =
      output "planning" "instance" "References readiness for this exact tunable-map revision." types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
in {
  interface = {
    inherit alias declaration document identity requestType observationType realizationType;
    methods = builtins.attrNames methods;
  };
  declarations.${alias} = declaration;
}
