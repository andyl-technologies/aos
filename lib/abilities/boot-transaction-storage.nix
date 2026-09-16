##! Provider-neutral boot transaction-storage view.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  requestType = types.record {
    fields = {
      name = types.localKey;
      purpose = types.enum ["initrd-stage-journal"];
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.boot.transaction-storage-observation/v1"];
      expected = requestType;
      realized = {
        type = types.optional types.executionPath;
        optional = true;
      };
      state = types.enum ["absent" "ready" "unknown"];
    };
  };
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.boot.transaction-storage-realization/v1"];
      path = types.executionPath;
    };
  };
  materialize = {
    description = "Materializes the selected initrd stage transaction journal.";
    semantics = {
      requiredTargetAccess = "exclusive-write";
      stopsProvider = false;
    };
    parameters = requestType;
    targetResource = "aos.boot.transaction-storage-view";
    permittedOperations = ["materialize"];
    guarantees = [];
    outputs = {
      observation =
        output "runtime" "attempt"
        "Reports the exact boot transaction-storage view state."
        observationType;
      retained-resource =
        output "runtime" "transaction"
        "References the exact retained boot transaction-storage view."
        types.resourceReference;
      storage-path =
        output "runtime" "transaction"
        "Returns the exact materialized transaction journal path."
        types.executionPath;
    };
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  declaration = declareInterface {
    name = "aos.boot.transaction-storage-view";
    description = "Materializes protected transaction storage before mutable host state is available.";
    abi = 1;
    inherit requestType;
    methods = {inherit materialize;};
    outputs = {
      storage-path =
        output "planning" "transaction"
        "Returns the selected transaction journal path."
        types.executionPath;
      storage-resource =
        output "planning" "transaction"
        "References the exact selected transaction-storage resource."
        types.resourceReference;
    };
    lifecycle.persistentDeleteMethod = null;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "boot-transaction-storage-view";
    };
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  view = {
    alias = "boot-transaction-storage-view";
    name = declaration.name;
    inherit declaration document requestType observationType realizationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
  };
in {
  interfaces = {inherit view;};
  declarations.${view.alias} = view.declaration;
}
