##! Provider-neutral persistence for runtime-produced content-addressed objects.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  canonicalList = element: maxItems:
    types.list {
      inherit element maxItems;
      unique = true;
      canonicalOrder = true;
    };
  requestType = types.record {
    fields = {
      name = types.localKey;
      media_type = types.string {
        maxLength = 255;
        syntax = null;
      };
      prerequisites = canonicalList (types.deferredResult types.resourceReference) 64;
    };
  };
  methodParameters = types.record {
    fields = {
      request = requestType;
      blob = types.optional (types.deferredResult types.transactionBlobReference);
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.artifact.content-addressed-object-observation/v1"];
      expected = requestType;
      state = types.enum ["absent" "ready" "drifted" "unknown"];
      content_sha256 = types.optional types.digest;
      artifact = types.optional types.artifactReference;
    };
  };
  realizationType = types.record {
    fields.schema = types.enum ["aos.artifact.content-addressed-object-realization/v1"];
  };
  output = schema: description: {
    inherit schema description;
    phase = "runtime";
    lifetime = "persistent";
    visibility = "protected";
  };
  method = name: description: access: stopsProvider: outputs: {
    inherit description outputs;
    parameters = methodParameters;
    targetResource = "aos.artifact.content-addressed-object";
    permittedOperations = [name];
    guarantees = [];
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  methods = {
    commit = method "commit" "Commits one checked transaction blob as a persistent content-addressed object." "exclusive-write" false {
      artifact-reference = output types.artifactReference "Returns the exact persistent artifact reference derived from the committed bytes.";
      artifact-resource = output types.resourceReference "References the exact persistent object and its observe and delete operations.";
      content-sha256 = output types.digest "Returns the runtime-derived digest of the committed source bytes.";
    };
    observe = method "observe" "Observes one persistent content-addressed object and reverifies its identity." "read" false {};
    remove = method "remove" "Deletes the persistent owner root for one content-addressed object." "exclusive-write" true {};
  };
  declaration = declareInterface {
    name = "aos.artifact.content-addressed-object";
    description = "Persists runtime-produced bytes by content identity without carrying filesystem paths through the effect graph.";
    abi = 1;
    inherit requestType methods;
    outputs = {};
    lifecycle.persistentDeleteMethod = "remove";
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "content-addressed-object";
    };
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
in {
  alias = "content-addressed-object";
  name = declaration.name;
  inherit declaration document requestType methodParameters observationType realizationType;
  identity = interfaceIdentity document;
  methods = builtins.attrNames methods;
  declarations.content-addressed-object = declaration;
}
