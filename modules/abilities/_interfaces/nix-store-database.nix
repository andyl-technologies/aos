##! Provider-neutral local Nix store database interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  alias = "nix-store-database";
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  registrationInput = types.record {
    fields = {
      path = types.executionPath;
      required = types.boolean;
    };
  };
  requestType = types.record {
    fields = {
      scope = types.enum ["local"];
      registration = types.optional registrationInput;
      prerequisites = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.nix-store-database-observation/v1"];
      expected = requestType;
      initialized = types.boolean;
      registration_digest = types.optional types.digest;
      registration_state = types.enum ["absent" "loaded" "not-requested" "partial" "unknown"];
      state = types.enum ["absent" "degraded" "ready" "unknown"];
    };
  };
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.nix.store-database-realization/v1"];
      nix_store = types.executableReference;
    };
  };
  lifecycle.persistentDeleteMethod = null;
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = alias;
  };
  observationOutput = phase:
    output phase "attempt"
    "Reports the exact observed local Nix store database state."
    observationType;
  retainedResourceOutput =
    output "runtime" "persistent"
    "References the exact converged Nix store database retained across provider instances."
    types.resourceReference;
  method = name: description: access: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      stopsProvider = false;
    };
    parameters = requestType;
    targetResource = "aos.nix.store-database";
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  methodDeclarations = {
    converge =
      method
      "converge"
      "Initializes the local Nix store database and imports the exact admitted registration stream."
      "exclusive-write"
      {
        observation = observationOutput "runtime";
        retained-resource = retainedResourceOutput;
      };
    observe =
      method
      "observe"
      "Observes whether the local Nix store database contains the exact admitted registration stream."
      "read"
      {observation = observationOutput "observation";};
  };
  declaration = declareInterface {
    name = "aos.nix.store-database";
    description = "Converges and observes one local Nix store database from an image registration stream.";
    abi = 1;
    inherit requestType lifecycle aggregation;
    methods = methodDeclarations;
    outputs.resource =
      output "planning" "persistent"
      "References readiness for the exact requested Nix store database revision."
      types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
  interface = {
    inherit alias declaration document identity requestType observationType realizationType lifecycle aggregation;
    methods = builtins.attrNames methodDeclarations;
    inherit methodDeclarations;
  };
  readView = {
    inherit interface;
    declarations.${alias} = declaration;
  };
in {
  name = "nixStoreDatabase";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
