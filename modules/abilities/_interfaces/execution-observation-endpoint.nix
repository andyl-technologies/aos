##! Provider-neutral execution-observation endpoint interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  interfaceName = "aos.execution.observation-endpoint";
  requestType = types.record {
    fields.endpoint = types.enum ["default"];
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.execution.observation-endpoint-observation/v1"];
      expected = requestType;
      state = types.enum ["available" "unavailable" "unknown"];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Discovers the selected protected endpoint for observing ability execution boundaries.";
    abi = 1;
    inherit requestType;
    methods.observe = {
      description = "Observes availability of the exact protected execution-boundary endpoint.";
      parameters = requestType;
      targetResource = interfaceName;
      permittedOperations = ["observe"];
      guarantees = [];
      semantics = {
        requiredTargetAccess = "read";
        stopsProvider = false;
      };
      outputs.observation =
        output
        "observation"
        "attempt"
        "Reports availability of the exact protected observation endpoint."
        observationType;
      outcome = {
        completionEvidence = observationType;
        observationEvidence = observationType;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
    outputs = {
      resource =
        output
        "planning"
        "instance"
        "References the endpoint and authorizes only observation."
        types.resourceReference;
      socket-path =
        output
        "planning"
        "instance"
        "Returns the protected local endpoint path."
        types.executionPath;
    };
    lifecycle.persistentDeleteMethod = null;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "execution-observation-endpoint";
    };
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  endpoint = {
    alias = "execution-observation-endpoint";
    name = declaration.name;
    inherit declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
  };
  libraryView = {
    interfaces = {inherit endpoint;};
    declarations.${endpoint.alias} = endpoint.declaration;
  };
in {
  name = "executionObservationEndpoint";
  readView = libraryView;
  module.config.aos.abilities.interfaces = libraryView.declarations;
}
