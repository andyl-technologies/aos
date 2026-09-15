##! Closed manager-neutral service declaration and observation types.
{types}: let
  boundedString = maxLength:
    types.string {
      inherit maxLength;
      syntax = null;
    };
  localKey = types.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  localKeys = types.list {
    element = localKey;
    maxItems = 256;
  };
  capabilityNames = types.list {
    element = types.capabilityName;
    maxItems = 256;
  };
  executionPath = types.executionPath;
  configurationPath = executionPath;
  credentialPath = executionPath;
  storagePath = executionPath;
  hostPath = executionPath;
  deviceNode = executionPath;
  rootDirectoryPath = executionPath;
  principalName = types.principalName;
  groupName = types.groupName;
  restartToken = boundedString 1024;
  command = types.record {
    fields = {
      executable = types.executableReference;
      ignore_failure = types.boolean;
    };
  };
  commands = types.list {
    element = command;
    maxItems = 64;
  };
  environmentFile = types.record {
    fields = {
      source = types.deferredResult configurationPath;
      optional = types.boolean;
    };
  };
  environmentFiles = types.list {
    element = environmentFile;
    maxItems = 64;
  };

  serviceBaseFields = {
    service = localKey;
    enabled = types.boolean;
  };
  feature = fields: optional:
    (types.record {
      inherit fields;
      inherit optional;
    })
    // {
      _serviceFeatureFields = fields;
      _serviceFeatureOptional = optional;
    };
  request = featureType:
    types.record {
      fields = serviceBaseFields // featureType._serviceFeatureFields;
      optional = featureType._serviceFeatureOptional;
    };

  lifecycleFeature = feature {
    description = boundedString 1024;
    execution_model = types.enum ["foreground" "forking" "oneshot"];
    working_directory = {
      type = types.optional (types.deferredResult executionPath);
      optional = true;
    };
    environment_files = environmentFiles;
    condition = commands;
    pre_start = commands;
    start = commands;
    post_start = commands;
    stop = commands;
    post_stop = commands;
    restart = types.enum ["always" "never" "on-failure"];
    restart_token = {
      type = types.optional restartToken;
      optional = true;
    };
    restart_delay_millis = types.integer {
      minimum = 0;
      maximum = 86400000;
    };
    remain_after_exit = types.boolean;
    start_timeout_millis = types.integer {
      minimum = 1;
      maximum = 86400000;
    };
    stop_timeout_millis = types.integer {
      minimum = 1;
      maximum = 86400000;
    };
  } [];
  lifecycle = request lifecycleFeature;
  dependenciesFeature = feature {
    after = types.list {
      element = types.deferredResult types.resourceReference;
      maxItems = 256;
    };
    before = types.list {
      element = types.deferredResult types.resourceReference;
      maxItems = 256;
    };
    requires = types.list {
      element = types.deferredResult types.resourceReference;
      maxItems = 256;
    };
    wants = types.list {
      element = types.deferredResult types.resourceReference;
      maxItems = 256;
    };
  } [];
  dependencies = request dependenciesFeature;
  readinessFeature = feature {
    mechanism = types.enum ["process-running" "process-signal" "socket-accepting" "successful-exit"];
    signal_scope = types.enum ["all-processes" "children" "main-process" "none"];
    timeout_millis = types.integer {
      minimum = 1;
      maximum = 86400000;
    };
  } [];
  readiness = request readinessFeature;
  reloadFeature = feature {
    strategy = types.enum ["command" "restart" "unsupported"];
    commands = commands;
  } [];
  reload = request reloadFeature;

  credentialView = types.record {
    fields = {
      name = localKey;
      reference = types.deferredResult credentialPath;
      encrypted = types.boolean;
      optional = types.boolean;
      environment_variable = {
        type = types.optional localKey;
        optional = true;
      };
    };
  };
  credentialsFeature = feature {
    views = types.list {
      element = credentialView;
      maxItems = 256;
    };
  } [];
  credentials = request credentialsFeature;

  configurationView = types.record {
    fields = {
      name = localKey;
      source = types.deferredResult configurationPath;
      optional = types.boolean;
    };
  };
  configurationFeature = feature {
    views = types.list {
      element = configurationView;
      maxItems = 256;
    };
  } [];
  configuration = request configurationFeature;

  storageMount = types.record {
    fields = {
      name = localKey;
      source = types.deferredResult storagePath;
      access = types.enum ["read-only" "read-write"];
    };
  };
  storageFeature = feature {
    mounts = types.list {
      element = storageMount;
      maxItems = 256;
    };
  } [];
  storage = request storageFeature;

  unixSocket = types.record {
    fields = {
      kind = types.enum ["unix"];
      path = types.deferredResult executionPath;
    };
  };
  networkSocket = types.record {
    fields = {
      kind = types.enum ["network"];
      address = boundedString 255;
      port = types.integer {
        minimum = 1;
        maximum = 65535;
      };
      transport = types.enum ["tcp" "udp"];
    };
  };
  socketEndpoint = types.taggedUnion {
    tag = "kind";
    variants = {
      network = networkSocket;
      unix = unixSocket;
    };
  };
  socket = types.record {
    fields = {
      name = localKey;
      endpoints = types.list {
        element = socketEndpoint;
        maxItems = 64;
      };
    };
  };
  socketActivationFeature = feature {
    sockets = types.list {
      element = socket;
      maxItems = 64;
    };
  } [];
  socketActivation = request socketActivationFeature;

  loggingFeature = feature {
    standard_output = types.enum ["console" "discard" "inherit" "structured" "structured-and-console"];
    standard_error = types.enum ["console" "discard" "inherit" "structured" "structured-and-console"];
    namespace = {
      type = types.optional localKey;
      optional = true;
    };
    directories = localKeys;
    directory_mode = types.fileMode;
  } [];
  logging = request loggingFeature;

  identityFeature = feature {
    principal = {
      type = types.optional (types.deferredResult principalName);
      optional = true;
    };
    primary_group = {
      type = types.optional (types.deferredResult groupName);
      optional = true;
    };
    supplementary_groups = types.list {
      element = types.deferredResult groupName;
      maxItems = 256;
    };
    ephemeral = types.boolean;
    file_creation_mask = types.fileMode;
  } [];
  identity = request identityFeature;

  hostPathAccess = types.record {
    fields = {
      source = types.deferredResult hostPath;
      mode = types.enum ["read-only" "read-write"];
    };
  };
  deviceAccess = types.record {
    fields = {
      source = types.deferredResult deviceNode;
      read = types.boolean;
      write = types.boolean;
      create_node = types.boolean;
    };
  };
  isolationFeature = feature {
    privilege = types.enum ["privileged" "unprivileged"];
    filesystem = types.enum ["host" "private" "read-only-system"];
    network = types.enum ["host" "none" "private"];
    process_visibility = types.enum ["host" "private"];
    termination_scope = types.enum ["all-processes" "main-process" "mixed"];
    temporary_directory = types.enum ["disconnected" "private" "shared"];
    devices = types.list {
      element = deviceAccess;
      maxItems = 256;
    };
    host_paths = types.list {
      element = hostPathAccess;
      maxItems = 256;
    };
    maximum_open_files = {
      type = types.optional (types.integer {
        minimum = 1;
        maximum = 2147483647;
      });
      optional = true;
    };
    maximum_processes = {
      type = types.optional (types.integer {
        minimum = 1;
        maximum = 2147483647;
      });
      optional = true;
    };
    maximum_tasks = {
      type = types.optional (types.integer {
        minimum = 1;
        maximum = 2147483647;
      });
      optional = true;
    };
    permit_core_dumps = types.boolean;
    root_directory = {
      type = types.optional (types.deferredResult rootDirectoryPath);
      optional = true;
    };
  } [];
  isolation = request isolationFeature;

  linuxIsolationFeature = feature {
    allow_privilege_escalation = types.boolean;
    ambient_capabilities = capabilityNames;
    bounding_capabilities = capabilityNames;
    control_group_delegation = types.boolean;
    control_group_access = types.enum ["host" "private" "read-only"];
    device_namespace = types.enum ["private" "shared"];
    kernel_clock_mutation = types.boolean;
    kernel_hostname_mutation = types.boolean;
    kernel_log_access = types.boolean;
    kernel_module_access = types.boolean;
    kernel_tunable_access = types.boolean;
    lock_personality = types.boolean;
    memory_write_execute = types.boolean;
    namespace_isolation = types.list {
      element = types.enum ["cgroup" "ipc" "mount" "network" "pid" "time" "user" "uts"];
      maxItems = 8;
    };
    network_address_families = types.list {
      element = types.enum ["ipv4" "ipv6" "netlink" "packet" "unix"];
      maxItems = 5;
    };
    oom_score_adjust = types.integer {
      minimum = -1000;
      maximum = 1000;
    };
    permit_realtime = types.boolean;
    permit_suid_sgid = types.boolean;
    process_visibility = types.enum ["all" "same-user" "self"];
    security_label = boundedString 4096;
    syscall_architectures = localKeys;
    syscall_allow = types.list {
      element = boundedString 128;
      maxItems = 256;
    };
    syscall_deny = types.list {
      element = boundedString 128;
      maxItems = 256;
    };
    syscall_profile = types.enum ["privileged" "restricted" "system-service"];
    user_namespace_ownership = types.enum ["full" "identity" "none" "self"];
  } [];
  linuxIsolation = request linuxIsolationFeature;

  inlineConfigurationSource = types.record {
    fields = {
      kind = types.enum ["inline-text"];
      content = boundedString 1048576;
    };
  };
  artifactConfigurationSource = types.record {
    fields = {
      kind = types.enum ["artifact-file"];
      reference = types.artifactFileReference;
    };
  };
  documentPathSegment = types.taggedUnion {
    tag = "kind";
    variants = {
      index = types.record {
        fields = {
          kind = types.enum ["index"];
          value = types.integer {
            minimum = 0;
            maximum = 65535;
          };
        };
      };
      key = types.record {
        fields = {
          kind = types.enum ["key"];
          value = boundedString 1024;
        };
      };
    };
  };
  documentPath = types.list {
    element = documentPathSegment;
    maxItems = 64;
  };
  documentNode = types.taggedUnion {
    tag = "kind";
    variants = {
      array = types.record {
        fields = {
          kind = types.enum ["array"];
          path = documentPath;
        };
      };
      boolean = types.record {
        fields = {
          kind = types.enum ["boolean"];
          path = documentPath;
          value = types.deferredResult types.boolean;
        };
      };
      integer = types.record {
        fields = {
          kind = types.enum ["integer"];
          path = documentPath;
          value = types.deferredResult (types.integer {
            minimum = -9007199254740991;
            maximum = 9007199254740991;
          });
        };
      };
      null = types.record {
        fields = {
          kind = types.enum ["null"];
          path = documentPath;
        };
      };
      object = types.record {
        fields = {
          kind = types.enum ["object"];
          path = documentPath;
        };
      };
      string = types.record {
        fields = {
          kind = types.enum ["string"];
          path = documentPath;
          value = types.deferredResult types.runtimeString;
        };
      };
    };
  };
  pathPrefix = length: path:
    builtins.genList (index: builtins.elemAt path index) length;
  structuredDocumentValid = source: let
    nodes = source.document;
    entries =
      builtins.map (node: {
        name = builtins.toJSON node.path;
        value = node;
      })
      nodes;
    nodesByPath = builtins.listToAttrs entries;
    root = nodesByPath.${builtins.toJSON []} or null;
    immediateChildren = parentPath:
      builtins.filter (node: let
        length = builtins.length node.path;
      in
        length
        == builtins.length parentPath + 1
        && pathPrefix (length - 1) node.path == parentPath)
      nodes;
    parentsValid = builtins.all (node: let
      length = builtins.length node.path;
    in
      length
      == 0
      || (let
        parentPath = pathPrefix (length - 1) node.path;
        parent = nodesByPath.${builtins.toJSON parentPath} or null;
        segment = builtins.elemAt node.path (length - 1);
      in
        parent
        != null
        && (
          (segment.kind == "key" && parent.kind == "object")
          || (segment.kind == "index" && parent.kind == "array")
        )))
    nodes;
    arraysContiguous = builtins.all (node:
      node.kind
      != "array"
      || (let
        children = immediateChildren node.path;
        indices = builtins.sort (left: right: left < right) (builtins.map
          (child: (builtins.elemAt child.path (builtins.length child.path - 1)).value)
          children);
      in
        indices == builtins.genList (index: index) (builtins.length indices)))
    nodes;
    formatValid =
      source.format
      != "toml"
      || (root != null && root.kind == "object" && builtins.all (node: node.kind != "null") nodes);
  in
    nodes
    != []
    && builtins.length nodes == builtins.length (builtins.attrNames nodesByPath)
    && root != null
    && parentsValid
    && arraysContiguous
    && formatValid;
  structuredConfigurationSourceBase = types.record {
    fields = {
      kind = types.enum ["structured-value"];
      format = types.enum ["json" "toml" "yaml"];
      document = types.list {
        element = documentNode;
        maxItems = 65536;
      };
    };
  };
  structuredConfigurationSource = types.refined {
    name = "structured configuration source";
    description = "a canonical rooted document tree with contiguous arrays";
    type = structuredConfigurationSourceBase;
    predicate = structuredDocumentValid;
  };
  configurationMaterializationSource = types.taggedUnion {
    tag = "kind";
    variants = {
      artifact-file = artifactConfigurationSource;
      inline-text = inlineConfigurationSource;
      structured-value = structuredConfigurationSource;
    };
  };
  configurationMaterialization = types.record {
    fields = {
      name = localKey;
      source = configurationMaterializationSource;
      mode = types.fileMode;
    };
  };
  configurationMaterializationState = types.enum ["absent" "failed" "materialized" "unknown"];
  configurationMaterializationObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.configuration-materialization-observation/v1"];
      expected = configurationMaterialization;
      materialized = {
        type = types.optional executionPath;
        optional = true;
      };
      state = configurationMaterializationState;
    };
  };

  networkReadiness = types.record {
    fields = {
      scope = types.enum ["configured-connectivity" "default-route" "local-connectivity"];
      address_families = types.list {
        element = types.enum ["ipv4" "ipv6"];
        maxItems = 2;
      };
    };
  };
  networkReadinessObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.network-readiness-observation/v1"];
      expected = networkReadiness;
      state = types.enum ["configuring" "degraded" "failed" "ready" "unknown"];
    };
  };

  referencedViewFields = {
    name = localKey;
    source = types.deferredResult types.resourceReference;
  };
  credentialDelivery = types.record {
    fields =
      referencedViewFields
      // {
        encrypted = types.boolean;
      };
  };
  storageView = types.record {
    fields =
      referencedViewFields
      // {
        access = types.enum ["read-only" "read-write"];
      };
  };
  storageAllocation = types.record {
    fields = {
      name = localKey;
      purpose = types.enum ["cache" "logs" "runtime" "state" "temporary"];
      mode = types.fileMode;
    };
  };
  hostPathView = types.record {
    fields =
      referencedViewFields
      // {
        access = types.enum ["read-only" "read-write"];
      };
  };
  deviceView = types.record {
    fields = referencedViewFields;
  };
  rootDirectoryView = types.record {
    fields = referencedViewFields;
  };
  identityResolutionFields = {
    name = localKey;
    allocation = types.enum ["ephemeral" "existing" "managed"];
  };
  principalResolution = types.record {
    fields = identityResolutionFields;
  };
  groupResolution = types.record {
    fields = identityResolutionFields;
  };
  producerState = types.enum ["absent" "failed" "ready" "unknown"];
  producerObservation = schema: expectedType: outputType:
    types.record {
      fields = {
        inherit schema;
        expected = expectedType;
        realized = {
          type = types.optional outputType;
          optional = true;
        };
        state = producerState;
      };
    };
  producerObservations = {
    credentialDelivery =
      producerObservation
      (types.enum ["aos.ability.credential-delivery-observation/v1"])
      credentialDelivery
      credentialPath;
    storageView =
      producerObservation
      (types.enum ["aos.ability.storage-view-observation/v1"])
      storageView
      storagePath;
    storageAllocation =
      producerObservation
      (types.enum ["aos.ability.storage-allocation-observation/v1"])
      storageAllocation
      storagePath;
    hostPathView =
      producerObservation
      (types.enum ["aos.ability.host-path-view-observation/v1"])
      hostPathView
      hostPath;
    deviceView =
      producerObservation
      (types.enum ["aos.ability.device-view-observation/v1"])
      deviceView
      deviceNode;
    rootDirectoryView =
      producerObservation
      (types.enum ["aos.ability.root-directory-view-observation/v1"])
      rootDirectoryView
      rootDirectoryPath;
    principalResolution =
      producerObservation
      (types.enum ["aos.ability.principal-resolution-observation/v1"])
      principalResolution
      principalName;
    groupResolution =
      producerObservation
      (types.enum ["aos.ability.group-resolution-observation/v1"])
      groupResolution
      groupName;
  };

  serviceDeclaration = types.record {
    fields =
      serviceBaseFields
      // {
        lifecycle = lifecycleFeature;
        dependencies = {
          type = types.optional dependenciesFeature;
          optional = true;
        };
        readiness = {
          type = types.optional readinessFeature;
          optional = true;
        };
        reload = {
          type = types.optional reloadFeature;
          optional = true;
        };
        credentials = {
          type = types.optional credentialsFeature;
          optional = true;
        };
        configuration = {
          type = types.optional configurationFeature;
          optional = true;
        };
        storage = {
          type = types.optional storageFeature;
          optional = true;
        };
        socket_activation = {
          type = types.optional socketActivationFeature;
          optional = true;
        };
        logging = {
          type = types.optional loggingFeature;
          optional = true;
        };
        identity = {
          type = types.optional identityFeature;
          optional = true;
        };
        isolation = {
          type = types.optional isolationFeature;
          optional = true;
        };
        linux_isolation = {
          type = types.optional linuxIsolationFeature;
          optional = true;
        };
      };
  };
  serviceResourceSchema = types.schemaOf "service resource" serviceDeclaration;

  lifecycleState = types.enum ["disabled" "failed" "inactive" "ready" "starting" "stopping" "unknown"];
  featureState = types.enum ["applied" "disabled" "failed" "pending" "unknown"];
  observationFor = feature: requestType: stateType: extraFields:
    types.record {
      fields =
        {
          schema = types.enum ["aos.ability.service-${feature}-observation/v1"];
          expected = requestType;
          observed = {
            type = types.optional requestType;
            optional = true;
          };
          discrepancies = localKeys;
          state = stateType;
        }
        // extraFields;
    };
  observations = {
    lifecycle = observationFor "lifecycle" lifecycle lifecycleState {
      process_id = {
        type = types.optional (types.integer {
          minimum = 1;
          maximum = 2147483647;
        });
        optional = true;
      };
    };
    dependencies = observationFor "dependencies" dependencies featureState {};
    readiness = observationFor "readiness" readiness lifecycleState {};
    reload = observationFor "reload" reload featureState {available = types.boolean;};
    credentials = observationFor "credentials" credentials featureState {};
    configuration = observationFor "configuration" configuration featureState {};
    storage = observationFor "storage" storage featureState {};
    socketActivation = observationFor "socket-activation" socketActivation featureState {};
    logging = observationFor "logging" logging featureState {};
    identity = observationFor "identity" identity featureState {};
    isolation = observationFor "isolation" isolation featureState {};
    linuxIsolation = observationFor "linux-isolation" linuxIsolation featureState {};
  };
in {
  inherit
    command
    commands
    serviceDeclaration
    serviceResourceSchema
    executionPath
    configurationPath
    credentialPath
    storagePath
    hostPath
    deviceNode
    rootDirectoryPath
    principalName
    groupName
    restartToken
    configurationMaterialization
    configurationMaterializationObservation
    networkReadiness
    networkReadinessObservation
    credentialDelivery
    storageView
    storageAllocation
    hostPathView
    deviceView
    rootDirectoryView
    principalResolution
    groupResolution
    producerObservations
    structuredConfigurationSource
    structuredDocumentValid
    lifecycle
    dependencies
    readiness
    reload
    credentials
    configuration
    storage
    socketActivation
    logging
    identity
    isolation
    linuxIsolation
    observations
    ;
  resourceReference = types.resourceReference;
}
