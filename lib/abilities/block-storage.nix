##! Canonical provider-neutral block-storage resources.
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
  ephemeralLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  persistentLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = false;
    retainsPersistentByDefault = true;
    persistentDeleteMethod = null;
  };
  prerequisites = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 64;
    unique = true;
    canonicalOrder = true;
  };
  resourceMethod = requestType: observationType: resourceName: name: description: access: stopsProvider: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = requestType;
    targetResource = resourceName;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  resource = {
    alias,
    name,
    description,
    requestType,
    observationType,
    action,
    actionDescription,
    releaseDescription,
    resultName,
    resultType,
    resultDescription,
    lifecycle,
  }: let
    observation = phase:
      output phase "attempt" "Reports the exact observed resource state." observationType;
    retained =
      output "runtime" "instance" "References the exact retained resource." types.resourceReference;
    methods = {
      ${action} = resourceMethod requestType observationType name action actionDescription "exclusive-write" false {
        observation = observation "runtime";
        retained-resource = retained;
        ${resultName} = output "runtime" "instance" resultDescription resultType;
      };
      observe = resourceMethod requestType observationType name "observe" "Observes the exact requested resource." "read" false {
        observation = observation "observation";
      };
      release = resourceMethod requestType observationType name "release" releaseDescription "exclusive-write" true {
        observation = observation "runtime";
      };
    };
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
    declaration = declareInterface {
      inherit name description requestType methods lifecycle aggregation;
      abi = 1;
      outputs.readiness-resource =
        output "planning" "instance" "References readiness for this exact resource revision." types.resourceReference;
      guarantees = [];
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

  encryptedMappingRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      source = types.deferredResult types.executionPath;
      cipher = types.string {
        maxLength = 128;
        syntax = "local-key-v1";
      };
      key_size_bits = types.integer {
        minimum = 128;
        maximum = 512;
      };
      key = types.taggedUnion {
        tag = "kind";
        variants.ephemeral-random = types.record {
          fields.kind = types.enum ["ephemeral-random"];
        };
      };
      inherit prerequisites;
    };
  };
  encryptedMappingObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.encrypted-block-mapping-observation/v1"];
      expected = encryptedMappingRequest;
      realized = {
        type = types.optional types.executionPath;
        optional = true;
      };
      state = types.enum ["absent" "ready" "drifted" "unmanaged" "unknown"];
    };
  };
  encryptedMapping = resource {
    alias = "encrypted-block-mapping";
    name = "aos.storage.encrypted-block-mapping";
    description = "Retains one provider-neutral encrypted block-device mapping.";
    requestType = encryptedMappingRequest;
    observationType = encryptedMappingObservation;
    action = "open";
    actionDescription = "Opens the exact requested encrypted block-device mapping.";
    releaseDescription = "Closes only the encrypted mapping owned by this resource.";
    resultName = "mapped-device";
    resultType = types.executionPath;
    resultDescription = "Returns the exact mapped block-device path.";
    lifecycle = ephemeralLifecycle;
  };

  storageFormatRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      source = types.deferredResult types.executionPath;
      format = types.enum ["swap"];
      policy = types.enum ["always" "if-absent"];
      inherit prerequisites;
    };
  };
  storageFormatObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.storage-format-observation/v1"];
      expected = storageFormatRequest;
      realized = {
        type = types.optional types.executionPath;
        optional = true;
      };
      state = types.enum ["absent" "ready" "drifted" "unmanaged" "unknown"];
    };
  };
  storageFormat = resource {
    alias = "storage-format";
    name = "aos.storage.format";
    description = "Converges one explicitly requested storage format without exposing a formatting tool.";
    requestType = storageFormatRequest;
    observationType = storageFormatObservation;
    action = "format";
    actionDescription = "Formats the exact storage path according to the explicit destructive policy.";
    releaseDescription = "Releases controller ownership without erasing the formatted storage.";
    resultName = "formatted-path";
    resultType = types.executionPath;
    resultDescription = "Returns the exact path whose requested format was observed.";
    lifecycle = ephemeralLifecycle;
  };

  poolName = types.refined {
    name = "storage pool name";
    description = "a bounded storage-pool identity";
    type = types.string {
      maxLength = 255;
      syntax = null;
    };
    predicate = value: builtins.match "[A-Za-z][A-Za-z0-9_.:-]*" value != null;
  };
  poolRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      pool = poolName;
      import_policy = types.enum ["force"];
      properties = {
        type = datasetProperties;
        default = {};
      };
      inherit prerequisites;
    };
  };
  poolObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.storage-pool-observation/v1"];
      expected = poolRequest;
      realized = {
        type = types.optional poolName;
        optional = true;
      };
      state = types.enum ["absent" "ready" "drifted" "unmanaged" "unknown"];
    };
  };
  pool = resource {
    alias = "storage-pool";
    name = "aos.storage.pool";
    description = "Imports and retains one provider-neutral storage pool.";
    requestType = poolRequest;
    observationType = poolObservation;
    action = "import";
    actionDescription = "Imports the exact requested storage pool without mounting its datasets.";
    releaseDescription = "Exports only the storage pool owned by this resource.";
    resultName = "pool-name";
    resultType = poolName;
    resultDescription = "Returns the exact imported storage-pool identity.";
    lifecycle = ephemeralLifecycle;
  };

  datasetName = types.refined {
    name = "storage dataset name";
    description = "a bounded relative hierarchical dataset identity";
    type = types.string {
      maxLength = 1024;
      syntax = null;
    };
    predicate = value:
      builtins.match "[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*" value != null;
  };
  datasetProperties = types.map {
    keyMaxLength = 255;
    keySyntax = null;
    maxEntries = 256;
    value = types.string {
      maxLength = 4096;
      syntax = null;
    };
  };
  datasetRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      pool = types.deferredResult poolName;
      dataset = datasetName;
      mountpoint = {
        type = types.optional types.executionPath;
        optional = true;
      };
      mount_options = {
        type = types.list {
          element = types.string {
            maxLength = 1024;
            syntax = null;
          };
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      properties = datasetProperties;
      inherit prerequisites;
    };
  };
  datasetObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.storage-dataset-observation/v1"];
      expected = datasetRequest;
      realized = {
        type = types.optional types.executionPath;
        optional = true;
      };
      state = types.enum ["absent" "ready" "drifted" "unmanaged" "unknown"];
    };
  };
  dataset = resource {
    alias = "storage-dataset";
    name = "aos.storage.dataset";
    description = "Creates, configures, and mounts one provider-neutral storage dataset.";
    requestType = datasetRequest;
    observationType = datasetObservation;
    action = "mount";
    actionDescription = "Converges and mounts the exact requested storage dataset.";
    releaseDescription = "Unmounts only the storage dataset owned by this resource without destroying data.";
    resultName = "mountpoint";
    resultType = types.optional types.executionPath;
    resultDescription = "Returns the exact mounted dataset path when the dataset is mounted.";
    lifecycle = ephemeralLifecycle;
  };

  partitionSize = types.refined {
    name = "partition size";
    description = "a positive integer with an optional K/M/G/T/P suffix";
    type = types.string {
      maxLength = 32;
      syntax = null;
    };
    predicate = value: builtins.match "[1-9][0-9]*[KMGTP]?" value != null;
  };
  uuid = types.refined {
    name = "UUID";
    description = "a canonical lower-case hyphenated UUID";
    type = types.string {
      maxLength = 36;
      syntax = null;
    };
    predicate = value:
      builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" value
      != null;
  };
  stableDevice = types.refined {
    name = "stable storage device path";
    description = "an immutable /dev/disk/by-id device identity";
    type = types.executionPath;
    predicate = value: builtins.match "/dev/disk/by-id/[^/]+" value != null;
  };
  partitionTarget = types.taggedUnion {
    tag = "kind";
    variants = {
      root-disk = types.record {
        fields.kind = types.enum ["root-disk"];
      };
      device = types.record {
        fields = {
          kind = types.enum ["device"];
          path = stableDevice;
        };
      };
    };
  };
  protectedPartitionTypes = [
    "163bea60-58c7-46e7-b69a-6846a5a688af"
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
    "b921b045-1df0-41c3-af44-4c6f280d3fae"
    "44479540-f297-41b2-9af7-d131d5f0458a"
    "72ec70a6-cf74-40e6-bd49-4bda08e8f224"
    "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"
    "df3300ce-d69f-4c92-978c-9bfb0f38d820"
    "d13c5d3b-b5d1-422a-b29f-9454fdc89d76"
    "b6ed5582-440b-4209-b8da-5ff7c419ea3d"
    "41092b05-9fc8-4523-994f-2def0408b176"
  ];
  partitionType = types.refined {
    name = "storage partition type";
    description = "a portable additive partition type or unreserved canonical GUID";
    type = types.string {
      maxLength = 64;
      syntax = null;
    };
    predicate = value:
      builtins.elem value ["linux-generic" "swap"]
      || (
        uuid.check value
        && !(builtins.elem value protectedPartitionTypes)
      );
  };
  partitionSpec = types.record {
    fields = {
      target = partitionTarget;
      label = types.string {
        maxLength = 36;
        syntax = "local-key-v1";
      };
      partition_type = partitionType;
      size_min = partitionSize;
      size_max = {
        type = types.optional partitionSize;
        optional = true;
      };
      weight = types.integer {
        minimum = 1;
        maximum = 2147483647;
      };
      format = {
        type = types.optional (types.enum ["ext4" "vfat" "swap"]);
        optional = true;
      };
      uuid = {
        type = types.optional uuid;
        optional = true;
      };
      grow = types.boolean;
      grow_fs = types.boolean;
      priority = types.integer {
        minimum = 0;
        maximum = 2147483647;
      };
    };
  };
  provisioningPlan = types.record {
    fields = {
      schema = types.enum ["aos.storage.provisioning-plan/v1"];
      source = types.enum ["operator" "fallback"];
      marker_uuid = uuid;
      measured_boot = types.boolean;
      partitions = types.map {
        keyMaxLength = 36;
        keySyntax = "local-key-v1";
        maxEntries = 256;
        value = partitionSpec;
      };
    };
  };
  provisioningRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      root_device = types.deferredResult types.executionPath;
      measured_boot = types.boolean;
      policy = types.record {
        fields = {
          initialize = types.enum ["if-unprovisioned"];
          committed_divergence = types.enum ["require-factory-reset"];
        };
      };
      inherit prerequisites;
    };
  };
  provisioningObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.storage-provisioning-observation/v1"];
      expected = provisioningRequest;
      committed_source = {
        type = types.optional (types.enum ["operator" "fallback"]);
        optional = true;
      };
      state = types.enum ["absent" "completed" "drifted" "pending" "unknown"];
    };
  };
  provisioningMethods = {
    commit = resourceMethod provisioningRequest provisioningObservation "aos.storage.provisioning" "commit" "Commits the exact storage plan once." "exclusive-write" false {
      observation = output "runtime" "attempt" "Reports the exact observed provisioning state." provisioningObservation;
      retained-resource = output "runtime" "transaction" "References the exact committed provisioning transaction." types.resourceReference;
      committed-source = output "runtime" "transaction" "Reports whether the exact committed plan came from operator or fallback policy." (types.enum ["operator" "fallback"]);
    };
    observe = resourceMethod provisioningRequest provisioningObservation "aos.storage.provisioning" "observe" "Observes the exact committed storage plan." "read" false {
      observation = output "observation" "attempt" "Reports the exact observed provisioning state." provisioningObservation;
    };
  };
  provisioningDeclaration = declareInterface {
    name = "aos.storage.provisioning";
    description = "Commits one exact authenticated storage layout and observes its durable provenance marker.";
    abi = 1;
    requestType = provisioningRequest;
    methods = provisioningMethods;
    lifecycle = persistentLifecycle;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "storage-provisioning";
    };
    outputs.readiness-resource = output "planning" "transaction" "References readiness for this exact provisioning transaction." types.resourceReference;
    guarantees = [];
  };
  provisioningDocument = interfaceDocumentFromDeclaration provisioningDeclaration;
  provisioning = {
    alias = "storage-provisioning";
    name = "aos.storage.provisioning";
    declaration = provisioningDeclaration;
    document = provisioningDocument;
    identity = interfaceIdentity provisioningDocument;
    methods = builtins.attrNames provisioningMethods;
    requestType = provisioningRequest;
    observationType = provisioningObservation;
  };
in {
  types = {
    inherit poolName datasetName datasetProperties stableDevice partitionType provisioningPlan;
  };
  interfaces = {
    inherit encryptedMapping storageFormat pool dataset provisioning;
  };
  declarations = {
    ${encryptedMapping.alias} = encryptedMapping.declaration;
    ${storageFormat.alias} = storageFormat.declaration;
    ${pool.alias} = pool.declaration;
    ${dataset.alias} = dataset.declaration;
    ${provisioning.alias} = provisioning.declaration;
  };
}
