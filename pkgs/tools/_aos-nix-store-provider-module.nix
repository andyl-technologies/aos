##! Package-owned Nix store database ability declarations.
{lib, ...}: let
  inherit (lib.abilities) declareInterface interfaceDocumentFromDeclaration interfaceIdentity types;

  interfaceName = "aos.nix.store-database";
  interfaceAlias = "nix-store-database";
  providerArtifact = lib.abilities.packageOutput {};

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
  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = false;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = "nix-store-database";
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  observationOutput = phase:
    output phase "attempt"
    "Reports the exact observed local Nix store database state."
    observationType;
  retainedResourceOutput =
    output "runtime" "instance"
    "References the exact converged Nix store database resource."
    types.resourceReference;
  method = name: description: access: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      stopsProvider = false;
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
    name = interfaceName;
    description = "Converges and observes one local Nix store database from an image registration stream.";
    abi = 1;
    inherit requestType methods lifecycle aggregation;
    outputs.readiness-resource =
      output "planning" "instance"
      "References readiness for the exact requested Nix store database revision."
      types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
in {
  config.aos.abilities = {
    interfaces.${interfaceAlias} = declaration;

    implementations.${interfaceAlias} = {
      description = "Converges a local Nix store database with the selected Nix executable.";
      interface = interfaceAlias;
      artifact = providerArtifact;
      methods = builtins.attrNames methods;
      guarantees = [];
      providerModule = {
        artifact = providerArtifact;
        path = "share/aos/providers/nix-store-database.nix";
      };
      handlerDescriptor = {
        artifact = providerArtifact;
        entryPoint = "bin/aos-nix-store-provider";
        arguments = requestType;
        result = observationType;
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };

    requirementTemplates.${interfaceAlias} = {
      description = "Requires convergence and observation of the local Nix store database.";
      inherit (identity) abi descriptor;
      interface = identity.name;
      methods = builtins.attrNames methods;
      guarantees = [];
      strength = "required";
      fallback = null;
    };
  };
}
