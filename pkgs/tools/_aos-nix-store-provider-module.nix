##! Package-owned Nix store database ability declarations.
{lib, ...}: let
  inherit (lib.abilities) declareInterface interfaceDocumentFromDeclaration interfaceIdentity types;

  contentObject = lib.abilities.interfaces.contentAddressedArtifacts;
  contentObjectOperations = contentObject.operationInterface;

  interfaceName = "aos.nix.store-database";
  interfaceAlias = "nix-store-database";
  effectsName = "aos.nix.store-database-effects";
  effectsAlias = "nix-store-database-effects";
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
      output "planning" "persistent"
      "References readiness for the exact requested Nix store database revision."
      types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
  effectsDeclaration = declareInterface {
    name = effectsName;
    description = "Executes admitted Nix store database operations for one exact controller-owned resource.";
    abi = 1;
    inherit requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = interfaceIdentity (interfaceDocumentFromDeclaration effectsDeclaration);
in {
  config.aos.abilities = {
    interfaces = {
      ${interfaceAlias} = declaration;
      ${effectsAlias} = effectsDeclaration;
    };

    implementations.${interfaceAlias} = {
      description = "Converges a local Nix store database through the checked package-owned controller.";
      interface = interfaceAlias;
      artifact = providerArtifact;
      methods = builtins.attrNames methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned terminal Nix store database handler.";
        accepted_interfaces = [effectsIdentity];
        methods = builtins.attrNames methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      providerModule = {
        artifact = providerArtifact;
        path = "share/aos/providers/nix-store-database.nix";
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };

    implementations.${effectsAlias} = {
      description = "Executes authorized Nix store database operations through the package-owned handler.";
      interface = effectsAlias;
      artifact = providerArtifact;
      methods = builtins.attrNames methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = providerArtifact;
        entryPoint = "libexec/aos-nix-store-provider";
        arguments = requestType;
        result = observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };

    implementations.content-addressed-object = {
      description = "Owns persistent content-addressed objects committed through the checked Nix-store effects interface.";
      interface = contentObject.identity;
      artifact = providerArtifact;
      methods = contentObject.methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned terminal content-object handler.";
        accepted_interfaces = [contentObjectOperations.identity];
        methods = contentObject.methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      providerModule = {
        artifact = providerArtifact;
        path = "share/aos/providers/content-addressed-object.nix";
      };
      desiredType = contentObject.realizationType;
      requiredFeatures = [];
    };

    implementations.${contentObjectOperations.alias} = {
      description = "Executes authorized content-object operations through the package-owned Nix-store handler.";
      interface = contentObjectOperations.identity;
      artifact = providerArtifact;
      methods = contentObject.methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = providerArtifact;
        entryPoint = "libexec/aos-nix-store-provider";
        arguments = contentObject.methodParameters;
        result = contentObject.observationType;
      };
      desiredType = null;
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
