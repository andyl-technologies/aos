##! Package-owned metadata terminals for one storage-provisioning transaction.
{
  config,
  lib,
  ...
}: let
  abilityTypes = lib.abilities.types;
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  configurationInput = lib.abilities.interfaces.configurationInput.types;
  networkBootstrap = lib.abilities.interfaces.networkConfiguration.interface.types.bootstrap;
  runtimeArtifact = lib.abilities.packageOutput {};

  optional = type: {
    type = abilityTypes.optional type;
    optional = true;
  };
  inherit (configurationInput) boundedText baseLibraryIdentity instanceFactsValue observedInstanceFacts authorizedInput;
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
  authorizationConfigurationType = abilityTypes.record {
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
  acquiredMetadata = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.acquired-provisioning-input/v1"];
      platform_id = platformId;
      host_module = optional boundedText;
      host_module_signature = optional boundedText;
      facts = instanceFactsValue;
    };
  };
  nativeTools = {
    blkid = abilityTypes.executableReference;
    mount = abilityTypes.executableReference;
    umount = abilityTypes.executableReference;
  };
  detectionParameters = abilityTypes.record {
    fields = {request = storage.requestType;} // nativeTools;
  };
  acquisitionParameters = abilityTypes.record {
    fields =
      {
        request = storage.requestType;
        platform = abilityTypes.deferredResult detectedPlatform;
      }
      // nativeTools;
  };
  authorizationParameters = abilityTypes.record {
    fields = {
      request = storage.requestType;
      configuration = authorizationConfigurationType;
      acquired_metadata = abilityTypes.deferredResult acquiredMetadata;
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
  acquisitionObservation = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.metadata.provisioning-acquisition-observation/v1"];
      platform_id = optional platformId;
      state = abilityTypes.enum ["ready" "acquired"];
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
  acquisitionAlias = "storage-provisioning-metadata-acquirer";
  acquisitionMethod = method {
    name = "acquire";
    description = "Acquires untrusted metadata through the detected platform implementation.";
    parameters = acquisitionParameters;
    evidence = acquisitionObservation;
    outputs = {
      acquired-metadata = output acquiredMetadata "Returns exact untrusted input and normalized observational facts.";
      network-bootstrap = output (abilityTypes.optional networkBootstrap) "Returns optional semantic early-network facts for the selected portable network provider.";
    };
  };
  acquisitionDeclaration = lib.abilities.declareInterface {
    name = "aos.metadata.storage-provisioning-acquisition";
    description = "Acquires one typed metadata result without exposing provider-private scratch state.";
    abi = 1;
    requestType = storage.requestType;
    methods.acquire = acquisitionMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = aggregation acquisitionAlias;
    guarantees = [];
  };
  authorizationAlias = "storage-provisioning-input-authorizer";
  authorizationMethod = method {
    name = "authorize";
    description = "Authorizes exact typed metadata input for one provisioning transaction.";
    parameters = authorizationParameters;
    evidence = authorizationObservation;
    outputs.authorized-provisioning-input = output authorizedInput "Returns the exact authenticated host module and base-library identity.";
    outputs.authorized-input-blob = output abilityTypes.transactionBlobReference "Carries the same canonical authorized input bytes into persistent artifact commitment.";
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
  handler = entryPoint: arguments: result: {
    artifact = runtimeArtifact;
    inherit entryPoint arguments result;
  };
  configured =
    config.aos.abilities.environment
    != null
    && config.aos.config.evalAtBoot.trust != null
    && config.aos.config.evalAtBoot.baseLib != null
    && config.aos.config.evalAtBoot.baseLibAbiHash != null;
  trust = config.aos.config.evalAtBoot.trust;
  configKeys = config.aos.apm.configKeys;
  keyFileContent = keys: "${lib.concatStringsSep "\n" keys}\n";
  configTrustAnchors =
    config.aos.initrdRuntime.renderedFileTrees.aos-metadata-provider;
  trustedConfigKeys =
    lib.mapAttrsToList (operator: keys: let
      content = keyFileContent keys;
    in {
      kind = "immutable-file";
      path = "${configTrustAnchors}/${operator}.pub";
      content_sha256 = "sha256:${builtins.hashString "sha256" content}";
    })
    configKeys;
  configuredAuthorization = {
    schema = "aos.metadata.provisioning-authorization-configuration/v1";
    trust_mode = trust;
    trusted_config_keys = trustedConfigKeys;
    base_library = {
      store_path = toString config.aos.config.evalAtBoot.baseLib;
      abi_hash = config.aos.config.evalAtBoot.baseLibAbiHash;
    };
  };
in {
  options.aos.metadata.storageProvisioning = {
    authorizationConfiguration = lib.mkOption {
      type = abilityTypes.optional authorizationConfigurationType;
      default = null;
      internal = true;
      readOnly = true;
      description = "Exact metadata authorization configuration derived once from the final system configuration.";
    };
  };

  config.aos.abilities = lib.mkMerge [
    {
      interfaces = {
        ${detectionAlias} = detectionDeclaration;
        ${acquisitionAlias} = acquisitionDeclaration;
        ${authorizationAlias} = authorizationDeclaration;
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
          handlerDescriptor = handler "bin/aos-metadata-acquisition-provider" detectionParameters detectionObservation;
          providerModule = null;
          desiredType = null;
          requiredFeatures = [];
        };
        ${acquisitionAlias} = {
          description = "Acquires typed metadata through the package-owned platform runtime.";
          artifact = runtimeArtifact;
          interface = lib.abilities.interfaceIdentity (
            lib.abilities.interfaceDocumentFromDeclaration acquisitionDeclaration
          );
          methods = ["acquire"];
          guarantees = [];
          handlerDescriptor = handler "bin/aos-metadata-acquisition-provider" acquisitionParameters acquisitionObservation;
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
          handlerDescriptor = handler "bin/aos-metadata-policy-provider" authorizationParameters authorizationObservation;
          providerModule = null;
          desiredType = null;
          requiredFeatures = [];
        };
      };

      instances = lib.mkIf (config.aos.abilities.environment != null) {
        ${detectionAlias}.implementation = detectionAlias;
        ${acquisitionAlias}.implementation = acquisitionAlias;
        ${authorizationAlias}.implementation = authorizationAlias;
      };
    }
  ];

  config.aos.metadata.storageProvisioning.authorizationConfiguration =
    lib.mkIf configured
    configuredAuthorization;

  config.aos.initrdRuntime.files.aos-metadata-provider = lib.mkIf configured (
    lib.mapAttrs' (operator: keys:
      lib.nameValuePair "${operator}.pub" (keyFileContent keys))
    configKeys
  );

  config.aos.initrdRuntime.artifacts.aos-metadata-provider = lib.mkIf configured (
    map
    (path:
      if abilityTypes.executionPath.check path
      then path
      else throw "aos-metadata-provider derived invalid initrd runtime artifact path '${path}'")
    (builtins.sort builtins.lessThan [
      (builtins.toString configTrustAnchors)
      (builtins.toString config.aos.config.evalAtBoot.baseLib)
    ])
  );
}
