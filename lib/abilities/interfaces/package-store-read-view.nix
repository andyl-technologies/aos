##! Provider-neutral package-store read-view interface.
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
    fields.scope = types.enum ["boot-image"];
  };
  locatorType = types.record {
    fields = {
      schema = types.enum ["aos.package-store.read-view-locator/v1"];
      identity_root = types.executionPath;
      read_root = types.executionPath;
      static_contract = types.executionPath;
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.package-store.read-view-observation/v1"];
      expected = requestType;
      locator = locatorType;
      state = types.enum ["available" "unavailable" "unknown"];
    };
  };
  observe = {
    description = "Observes the selected package-store read view for the booted image.";
    parameters = requestType;
    targetResource = "aos.package-store.read-view";
    permittedOperations = ["observe"];
    guarantees = [];
    semantics = {
      requiredTargetAccess = "read";
      stopsProvider = false;
    };
    outputs = {
      observation =
        output "observation" "attempt"
        "Reports whether the selected package-store read view is available."
        observationType;
    };
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  declaration = declareInterface {
    name = "aos.package-store.read-view";
    description = "Exposes one selected immutable read view without encoding its backing filesystem layout.";
    abi = 1;
    inherit requestType;
    methods = {inherit observe;};
    outputs = {
      locator =
        output "planning" "persistent"
        "Returns the authenticated locator for the selected immutable package-store view."
        locatorType;
      resource =
        output "planning" "persistent"
        "References the selected immutable package-store read view."
        types.resourceReference;
    };
    lifecycle.persistentDeleteMethod = null;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "package-store-read-view";
    };
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  readView = {
    alias = "package-store-read-view";
    name = declaration.name;
    inherit declaration document requestType locatorType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
  };
  libraryView = {
    interfaces = {inherit readView;};
    declarations.${readView.alias} = readView.declaration;
  };
in {
  name = "packageStoreReadView";
  readView = libraryView;
  module.config.aos.abilities.interfaces = libraryView.declarations;
}
