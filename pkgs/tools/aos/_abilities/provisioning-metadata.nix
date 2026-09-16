##! Package-owned metadata terminals for one storage-provisioning transaction.
{
  config,
  lib,
  packageName,
  ...
}: let
  cfg = config.aos.metadata.storageProvisioning;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  networkBootstrap = lib.abilities.interfaces.networkConfiguration.interface.types.bootstrap;
  runtimeArtifact = lib.abilities.packageOutput {output = "metadataRuntime";};
  consumerInstance = "metadata-provisioning";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";
  registrySnapshot =
    config.aos.abilities.interfaces."${packageName}:synchronized-registry-snapshot".methods.observe.outputs.registry-snapshot.schema;

  optional = type: {
    type = abilityTypes.optional type;
    optional = true;
  };
  boundedText = abilityTypes.string {
    # Leave room for the envelope and evidence below the handler result bound.
    maxLength = 131072;
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
  factText = maxLength:
    abilityTypes.string {
      inherit maxLength;
      syntax = null;
    };
  staticNetworkFacts = abilityTypes.record {
    fields = {
      mac = abilityTypes.optional (factText 32);
      interface_name = abilityTypes.optional (factText 64);
      addresses = abilityTypes.list {
        element = factText 128;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      gateway = abilityTypes.optional (factText 128);
      dns = abilityTypes.list {
        element = factText 128;
        maxItems = 32;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  instanceFactsValue = abilityTypes.record {
    fields = {
      hostname = abilityTypes.optional (factText 253);
      ssh_authorized_keys = abilityTypes.list {
        element = factText 16384;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      instance_id = abilityTypes.optional (factText 1024);
      region = abilityTypes.optional (factText 256);
      availability_zone = abilityTypes.optional (factText 256);
      mac_to_iface = abilityTypes.list {
        element = abilityTypes.record {
          fields = {
            mac = factText 32;
            iface = factText 64;
          };
        };
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      disk_ids = abilityTypes.list {
        element = factText 512;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      network = abilityTypes.optional staticNetworkFacts;
    };
  };
  observedInstanceFacts = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.observed-instance-facts/v1"];
      trust = abilityTypes.enum ["unauthenticated-observational"];
      value = instanceFactsValue;
      sha256 = abilityTypes.digest;
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
  platformId = abilityTypes.enum [
    "aos-metadata"
    "nocloud"
    "config-drive"
    "qemu"
    "aws"
    "gcp"
    "azure"
    "digitalocean"
    "openstack"
    "metal"
    "hyperv"
    "vmware"
    "virtualbox"
  ];
  detectedPlatform = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-platform/v1"];
      platform_id = platformId;
      need_network = abilityTypes.boolean;
    };
  };
  detectionParameters = abilityTypes.record {
    fields.request = storage.requestType;
  };
  authorizationParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      configuration = authorizationConfiguration;
      platform = abilityTypes.deferredResult detectedPlatform;
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
      facts = observedInstanceFacts;
      base_library = baseLibraryIdentity;
    };
  };
  observerParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      authorized_input = abilityTypes.deferredResult authorizedInput;
      marker = abilityTypes.deferredResult lib.abilities.interfaces.blockStorage.types.provisioningMarkerObservation;
    };
  };
  authorizedInputSource = abilityTypes.taggedUnion {
    tag = "kind";
    variants = {
      direct-result = abilityTypes.record {
        fields = {
          kind = abilityTypes.enum ["direct-result"];
          input = abilityTypes.deferredResult authorizedInput;
        };
      };
      retained-artifact = abilityTypes.record {
        fields = {
          kind = abilityTypes.enum ["retained-artifact"];
          artifact = abilityTypes.deferredResult abilityTypes.artifactReference;
          content_sha256 = abilityTypes.deferredResult abilityTypes.digest;
        };
      };
    };
  };
  evaluationParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      authorized_input = authorizedInputSource;
      registry_snapshot = abilityTypes.deferredResult registrySnapshot;
    };
  };
  evaluationResult = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.configuration.provisioning-evaluation-result/v1"];
      controller = abilityTypes.resourceReference;
      handoff = abilityTypes.resourceReference;
      manifest_blob = abilityTypes.transactionBlobReference;
      manifest_sha256 = abilityTypes.digest;
      registry_snapshot_sha256 = abilityTypes.digest;
      host_module_sha256 = optional abilityTypes.digest;
      instance_facts_sha256 = abilityTypes.digest;
    };
  };
  authorizationObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-authorization-observation/v1"];
      source = optional (abilityTypes.enum ["operator" "fallback"]);
      state = abilityTypes.enum ["ready" "authorized"];
    };
  };
  detectionObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-platform-observation/v1"];
      platform_id = optional platformId;
      state = abilityTypes.enum ["ready" "detected"];
    };
  };
  planObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-plan-observation/v1"];
      source = optional (abilityTypes.enum ["operator" "fallback"]);
      state = abilityTypes.enum ["ready" "planned"];
    };
  };
  evaluationObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.configuration.provisioning-evaluation-observation/v1"];
      manifest_sha256 = optional abilityTypes.digest;
      state = abilityTypes.enum ["ready" "evaluated"];
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
    access ? "exclusive-write",
  }: {
    inherit description parameters outputs;
    semantics = {
      requiredTargetAccess = access;
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
  detectionAlias = "storage-provisioning-platform-detector";
  detectionMethod = method {
    name = "detect";
    description = "Detects the exact metadata platform and whether acquisition needs network readiness.";
    parameters = detectionParameters;
    evidence = detectionObservation;
    access = "read";
    outputs = {
      platform = output detectedPlatform "Returns the exact detected metadata platform for acquisition.";
      need-network = output abilityTypes.boolean "Selects the network preparation branch for cloud metadata.";
    };
  };
  detectionDeclaration = lib.abilities.declareInterface {
    name = "aos.metadata.storage-provisioning-platform-detection";
    description = "Detects metadata acquisition requirements before fetching untrusted input.";
    abi = 1;
    requestType = storage.requestType;
    methods.detect = detectionMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = aggregation detectionAlias;
    guarantees = [];
  };
  authorizationAlias = "storage-provisioning-input-authorizer";
  authorizationMethod = method {
    name = "authorize";
    description = "Acquires and authorizes the exact metadata input for one provisioning transaction.";
    parameters = authorizationParameters;
    evidence = authorizationObservation;
    outputs.authorized-provisioning-input = output authorizedInput "Returns the exact authenticated host module and base-library identity.";
    outputs.authorized-input-blob = output abilityTypes.transactionBlobReference "Carries the same canonical authorized input bytes into persistent artifact commitment.";
    outputs.network-bootstrap = output (abilityTypes.optional networkBootstrap) "Returns optional semantic early-network facts for the selected portable network provider.";
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
  evaluatorAlias = "storage-provisioning-configuration-evaluator";
  evaluatorMethod = method {
    name = "evaluate";
    description = "Evaluates authenticated provisioning input against one synchronized registry snapshot.";
    parameters = evaluationParameters;
    evidence = evaluationObservation;
    outputs.configuration-result = output evaluationResult "Returns the graph-bound manifest blob identity and exact evaluation authorities.";
  };
  evaluatorDeclaration = lib.abilities.declareInterface {
    name = "aos.configuration.storage-provisioning-evaluation";
    description = "Evaluates one authorized provisioning input into a canonical configuration manifest blob.";
    abi = 1;
    requestType = storage.requestType;
    methods.evaluate = evaluatorMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = aggregation evaluatorAlias;
    guarantees = [];
  };
  handler = arguments: result: {
    artifact = runtimeArtifact;
    entryPoint = "libexec/aos-metadata-provisioning-provider";
    inherit arguments result;
  };
in {
  options.aos.metadata.storageProvisioning = {
    authorizationConfiguration = lib.mkOption {
      type = abilityTypes.optional authorizationConfiguration;
      default = null;
      internal = true;
      readOnly = true;
      description = "Exact metadata authorization configuration derived once from the final system configuration.";
    };
    request = lib.mkOption {
      type = abilityTypes.optional storage.requestType;
      default = null;
      internal = true;
      readOnly = true;
      description = "Static first-boot provisioning intent admitted by the initrd ability graph.";
    };
  };

  config.aos.abilities = lib.mkMerge [
    {
      interfaces = {
        ${detectionAlias} = detectionDeclaration;
        ${authorizationAlias} = authorizationDeclaration;
        ${observerAlias} = observerDeclaration;
        ${evaluatorAlias} = evaluatorDeclaration;
      };

      implementations = {
        ${detectionAlias} = {
          description = "Detects metadata acquisition requirements through the package-owned metadata runtime.";
          artifact = runtimeArtifact;
          interface = lib.abilities.interfaceIdentity (
            lib.abilities.interfaceDocumentFromDeclaration detectionDeclaration
          );
          methods = ["detect"];
          guarantees = [];
          handlerDescriptor = handler detectionParameters detectionObservation;
          providerModule = null;
          desiredType = null;
          requiredFeatures = [];
        };
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
        ${evaluatorAlias} = {
          description = "Evaluates authorized provisioning input through the package-owned full configuration runtime.";
          artifact = runtimeArtifact;
          interface = lib.abilities.interfaceIdentity (
            lib.abilities.interfaceDocumentFromDeclaration evaluatorDeclaration
          );
          methods = ["evaluate"];
          guarantees = [];
          handlerDescriptor = handler evaluationParameters evaluationObservation;
          providerModule = null;
          desiredType = null;
          requiredFeatures = [];
        };
      };

      instances = lib.mkIf (config.aos.abilities.environment != null) {
        ${detectionAlias}.implementation = detectionAlias;
        ${authorizationAlias}.implementation = authorizationAlias;
        ${observerAlias}.implementation = observerAlias;
        ${evaluatorAlias}.implementation = evaluatorAlias;
      };
    }
    (lib.mkIf (initrdStage && cfg.request != null) (lib.mkMerge [
      (serviceManagement.forProducer {
        inherit consumerInstance;
        key = "provisioning";
        interface = storage;
        methods = ["commit" "observe"];
        parameters = cfg.request;
      })
      {instances.${consumerInstance} = {};}
    ]))
  ];
}
