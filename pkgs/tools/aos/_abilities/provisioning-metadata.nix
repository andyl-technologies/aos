##! Package-owned metadata terminals for one storage-provisioning transaction.
{
  config,
  lib,
  ...
}: let
  abilityTypes = lib.abilities.types;
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  serviceTypes = lib.abilities.interfaces.serviceManagement.types;
  runtimeArtifact = lib.abilities.packageOutput {output = "metadataRuntime";};

  optional = type: {
    type = abilityTypes.optional type;
    optional = true;
  };
  boundedText = abilityTypes.string {
    # Leave room for the envelope and evidence below the handler result bound.
    maxLength = 131072;
    syntax = null;
  };
  networkSeed = abilityTypes.string {
    # Metadata renderers produce a small networkd document. Keep the separate
    # runtime output well below the provider-result envelope bound.
    maxLength = 32768;
    syntax = null;
  };
  trustedKeyFile = abilityTypes.taggedUnion {
    tag = "kind";
    variants = {
      artifact-file = abilityTypes.record {
        fields = {
          kind = abilityTypes.enum ["artifact-file"];
          reference = abilityTypes.artifactPathReference;
        };
      };
      immutable-file = abilityTypes.record {
        fields = {
          kind = abilityTypes.enum ["immutable-file"];
          path = abilityTypes.executionPath;
          content_sha256 = abilityTypes.digest;
        };
      };
    };
  };
  baseLibraryIdentity = abilityTypes.record {
    fields = {
      store_path = abilityTypes.executionPath;
      abi_hash = abilityTypes.digest;
    };
  };
  authorizationConfiguration = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-authorization-configuration/v1"];
      trust_mode = abilityTypes.enum ["platform" "signed"];
      trusted_config_keys = abilityTypes.list {
        element = trustedKeyFile;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      base_library = baseLibraryIdentity;
    };
  };
  authorizationParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      configuration = authorizationConfiguration;
    };
  };
  authorizedInput = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.authorized-provisioning-input/v1"];
      source = abilityTypes.enum ["operator" "fallback"];
      host_module = optional boundedText;
      host_module_sha256 = optional abilityTypes.digest;
      authorization = abilityTypes.record {
        fields = {
          trust_mode = abilityTypes.enum ["platform" "signed"];
          platform_id = abilityTypes.string {
            maxLength = 128;
            syntax = "local-key-v1";
          };
          signer = optional (abilityTypes.string {
            maxLength = 512;
            syntax = null;
          });
        };
      };
      base_library = baseLibraryIdentity;
    };
  };
  observerParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      authorized_input = abilityTypes.deferredResult authorizedInput;
    };
  };
  seedParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      network_seed = abilityTypes.deferredResult (abilityTypes.optional networkSeed);
      storage_view = abilityTypes.deferredResult abilityTypes.resourceReference;
      storage_path = abilityTypes.deferredResult serviceTypes.storagePath;
    };
  };
  authorizationObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-authorization-observation/v1"];
      source = optional (abilityTypes.enum ["operator" "fallback"]);
      state = abilityTypes.enum ["ready" "authorized"];
    };
  };
  planObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-plan-observation/v1"];
      source = optional (abilityTypes.enum ["operator" "fallback"]);
      state = abilityTypes.enum ["ready" "planned"];
    };
  };
  seedObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-network-seed-observation/v1"];
      content_sha256 = optional abilityTypes.digest;
      state = abilityTypes.enum ["ready" "absent" "seeded"];
    };
  };
  output = schema: description: {
    inherit schema description;
    phase = "runtime";
    lifetime = "transaction";
    visibility = "protected";
  };
  method = {
    name,
    description,
    parameters,
    evidence,
    outputs,
  }: {
    inherit description parameters outputs;
    semantics = {
      requiredTargetAccess = "exclusive-write";
      stopsProvider = false;
    };
    targetResource = storage.identity.name;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = evidence;
      observationEvidence = evidence;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  aggregation = alias: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = alias;
  };
  authorizationAlias = "storage-provisioning-input-authorizer";
  authorizationMethod = method {
    name = "authorize";
    description = "Acquires and authorizes the exact metadata input for one provisioning transaction.";
    parameters = authorizationParameters;
    evidence = authorizationObservation;
    outputs.authorized-provisioning-input = output authorizedInput "Returns the exact authenticated host module and base-library identity.";
    outputs.network-seed = output (abilityTypes.optional networkSeed) "Returns the optional metadata-derived network seed for the post-provisioning storage view.";
  };
  authorizationDeclaration = lib.abilities.declareInterface {
    name = "aos.metadata.storage-provisioning-input-authorization";
    description = "Authorizes one metadata input without exposing an ambient cross-provider file.";
    abi = 1;
    requestType = storage.requestType;
    methods.authorize = authorizationMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = aggregation authorizationAlias;
    guarantees = [];
  };
  observerAlias = "storage-provisioning-plan-observer";
  observerMethod = method {
    name = "observe";
    description = "Evaluates one authenticated metadata input into its canonical storage plan.";
    parameters = observerParameters;
    evidence = planObservation;
    outputs.provisioning-plan = output lib.abilities.interfaces.blockStorage.types.provisioningPlan "Returns the exact canonical plan consumed by the provisioning terminal.";
  };
  observerDeclaration = lib.abilities.declareInterface {
    name = "aos.metadata.storage-provisioning-plan";
    description = "Evaluates authenticated metadata into a canonical storage plan.";
    abi = 1;
    requestType = storage.requestType;
    methods.observe = observerMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = aggregation observerAlias;
    guarantees = [];
  };
  seedAlias = "storage-provisioning-network-seeder";
  seedMethod = method {
    name = "seed";
    description = "Writes the authorized metadata network seed through the exact realized storage view.";
    parameters = seedParameters;
    evidence = seedObservation;
    outputs = {};
  };
  seedDeclaration = lib.abilities.declareInterface {
    name = "aos.metadata.storage-provisioning-network-seed";
    description = "Seeds metadata-derived networking into an authorized post-provisioning storage view.";
    abi = 1;
    requestType = storage.requestType;
    methods.seed = seedMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = aggregation seedAlias;
    guarantees = [];
  };
  handler = arguments: result: {
    artifact = runtimeArtifact;
    entryPoint = "libexec/aos-metadata-provisioning-provider";
    inherit arguments result;
  };
in {
  options.aos.metadata.storageProvisioning.authorizationConfiguration = lib.mkOption {
    type = abilityTypes.optional authorizationConfiguration;
    default = null;
    internal = true;
    readOnly = true;
    description = "Exact metadata authorization configuration derived once from the final system configuration.";
  };

  config.aos.abilities = {
    interfaces = {
      ${authorizationAlias} = authorizationDeclaration;
      ${observerAlias} = observerDeclaration;
      ${seedAlias} = seedDeclaration;
    };

    implementations = {
      ${authorizationAlias} = {
        description = "Authorizes metadata input through the package-owned metadata runtime.";
        artifact = runtimeArtifact;
        interface = lib.abilities.interfaceIdentity (
          lib.abilities.interfaceDocumentFromDeclaration authorizationDeclaration
        );
        methods = ["authorize"];
        guarantees = [];
        handlerDescriptor = handler authorizationParameters authorizationObservation;
        providerModule = null;
        desiredType = null;
        requiredFeatures = [];
      };
      ${observerAlias} = {
        description = "Evaluates authenticated metadata through the package-owned metadata runtime.";
        artifact = runtimeArtifact;
        interface = lib.abilities.interfaceIdentity (
          lib.abilities.interfaceDocumentFromDeclaration observerDeclaration
        );
        methods = ["observe"];
        guarantees = [];
        handlerDescriptor = handler observerParameters planObservation;
        providerModule = null;
        desiredType = null;
        requiredFeatures = [];
      };
      ${seedAlias} = {
        description = "Seeds metadata networking through the package-owned metadata runtime.";
        artifact = runtimeArtifact;
        interface = lib.abilities.interfaceIdentity (
          lib.abilities.interfaceDocumentFromDeclaration seedDeclaration
        );
        methods = ["seed"];
        guarantees = [];
        handlerDescriptor = handler seedParameters seedObservation;
        providerModule = null;
        desiredType = null;
        requiredFeatures = [];
      };
    };

    instances = lib.mkIf (config.aos.abilities.environment != null) {
      ${authorizationAlias}.implementation = authorizationAlias;
      ${observerAlias}.implementation = observerAlias;
      ${seedAlias}.implementation = seedAlias;
    };
  };
}
