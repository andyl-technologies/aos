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
  capabilityBounds = types.taggedUnion {
    tag = "kind";
    variants = {
      restricted = types.record {
        fields = {
          kind = types.enum ["restricted"];
          capabilities = capabilityNames;
        };
      };
      unrestricted = types.record {
        fields.kind = types.enum ["unrestricted"];
      };
    };
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
  signalName = boundedString 64;
  statusCode = types.integer {
    minimum = 0;
    maximum = 255;
  };
  durationMillis = types.integer {
    minimum = 0;
    maximum = 9007199254740991;
  };
  positiveDurationMillis = types.integer {
    minimum = 1;
    maximum = 9007199254740991;
  };
  resourceLimit = types.taggedUnion {
    tag = "kind";
    variants = {
      maximum = types.record {
        fields = {
          kind = types.enum ["maximum"];
          value = types.integer {
            minimum = 0;
            maximum = 9007199254740991;
          };
        };
      };
      unbounded = types.record {
        fields.kind = types.enum ["unbounded"];
      };
    };
  };
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
  environmentVariable = types.deferredResult types.runtimeString;
  environmentVariables = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 256;
    value = environmentVariable;
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
    configuration_change_action = {
      type = types.enum ["none" "reload" "restart"];
      default = "restart";
    };
    remain_after_exit = types.boolean;
    start_timeout_millis = types.integer {
      minimum = 1;
      maximum = 86400000;
    };
    start_timeout_unbounded = {
      type = types.boolean;
      default = false;
    };
    stop_timeout_millis = types.integer {
      minimum = 1;
      maximum = 86400000;
    };
    stop_timeout_unbounded = {
      type = types.boolean;
      default = false;
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
    requisite = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    conflicts = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    binds_to = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    part_of = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    upholds = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    required_by = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    wanted_by = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    required_mounts = {
      type = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
      default = [];
    };
    implicit_dependencies = {
      type = types.boolean;
      default = true;
    };
  } [];
  dependencies = request dependenciesFeature;

  pathCondition = types.record {
    fields = {
      kind = types.enum ["path"];
      predicate = types.enum ["exists" "is-directory" "is-mount-point" "is-nonempty"];
      path = types.deferredResult executionPath;
      negated = types.boolean;
    };
  };
  kernelArgumentCondition = types.record {
    fields = {
      kind = types.enum ["kernel-argument"];
      argument = boundedString 4096;
      negated = types.boolean;
    };
  };
  facilityCondition = types.record {
    fields = {
      kind = types.enum ["facility"];
      facility = localKey;
      negated = types.boolean;
    };
  };
  condition = types.taggedUnion {
    tag = "kind";
    variants = {
      path = pathCondition;
      kernel-argument = kernelArgumentCondition;
      facility = facilityCondition;
    };
  };
  conditionsFeature = feature {
    all = types.list {
      element = condition;
      maxItems = 256;
    };
  } [];
  conditions = request conditionsFeature;

  instantiationFeature = feature {
    kind = types.enum ["singleton" "template" "instance"];
    template = {
      type = types.optional localKey;
      optional = true;
    };
    instance = {
      type = types.optional (boundedString 1024);
      optional = true;
    };
  } [];
  instantiation = request instantiationFeature;

  supervisionFeature = feature {
    startup_protocol = types.enum ["process" "notification" "bus-name"];
    notification_access = types.enum ["none" "main-process" "all-processes"];
    bus_name = {
      type = types.optional (boundedString 255);
      optional = true;
    };
  } [];
  supervision = request supervisionFeature;
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
    strategy = types.enum ["command" "restart" "signal" "unsupported"];
    commands = commands;
    signal = {
      type = types.optional signalName;
      optional = true;
    };
    completion = {
      type = types.optional (types.enum ["command-exit" "notification"]);
      optional = true;
    };
  } [];
  reload = request reloadFeature;

  terminationFeature = feature {
    signal = signalName;
    final_signal = {
      type = types.optional signalName;
      optional = true;
    };
    process_id_file = {
      type = types.optional (types.deferredResult executionPath);
      optional = true;
    };
    send_to_all_processes = types.boolean;
  } [];
  termination = request terminationFeature;

  watchdogFeature = feature {
    timeout_millis = positiveDurationMillis;
    action = types.enum ["restart" "stop"];
  } [];
  watchdog = request watchdogFeature;

  startPolicyFeature = feature {
    accepted_exit_statuses = types.list {
      element = statusCode;
      maxItems = 256;
    };
    restart_preventing_exit_statuses = types.list {
      element = statusCode;
      maxItems = 256;
    };
    rate_interval_millis = {
      type = types.optional positiveDurationMillis;
      optional = true;
    };
    rate_burst = {
      type = types.optional (types.integer {
        minimum = 1;
        maximum = 4294967295;
      });
      optional = true;
    };
  } [];
  startPolicy = request startPolicyFeature;

  failurePolicyFeature = feature {
    handlers = types.list {
      element = types.deferredResult types.resourceReference;
      maxItems = 256;
    };
    dispatch = types.enum ["enqueue" "replace-active-goal"];
  } [];
  failurePolicy = request failurePolicyFeature;

  schedulingFeature = feature {
    nice = types.integer {
      minimum = -20;
      maximum = 19;
    };
    io_class = types.enum ["best-effort" "idle" "realtime"];
    io_priority = types.integer {
      minimum = 0;
      maximum = 7;
    };
  } [];
  scheduling = request schedulingFeature;

  resourcesFeature =
    feature {
      open_files = resourceLimit;
      processes = resourceLimit;
      tasks = resourceLimit;
      locked_memory_bytes = resourceLimit;
      memory_high_bytes = resourceLimit;
      memory_max_bytes = resourceLimit;
    } [
      "open_files"
      "processes"
      "tasks"
      "locked_memory_bytes"
      "memory_high_bytes"
      "memory_max_bytes"
    ];
  resources = request resourcesFeature;

  environmentFeature = feature {
    variables = environmentVariables;
    search_path = types.list {
      element = types.artifactSelector;
      maxItems = 256;
    };
  } [];
  environment = request environmentFeature;

  managedDirectory = types.record {
    fields = {
      name = localKey;
      purpose = types.enum ["cache" "logs" "runtime" "state"];
      mode = types.fileMode;
      retention = types.enum ["service-lifetime" "restart" "persistent"];
      owner = {
        type = types.optional (types.deferredResult principalName);
        optional = true;
      };
      group = {
        type = types.optional (types.deferredResult groupName);
        optional = true;
      };
    };
  };
  directoriesFeature = feature {
    managed = types.list {
      element = managedDirectory;
      maxItems = 256;
    };
  } [];
  directories = request directoriesFeature;

  activationBinding = types.record {
    fields = {
      name = localKey;
      resource = types.deferredResult types.resourceReference;
      relationship = types.enum ["dependency" "membership" "trigger"];
    };
  };
  activationFeature = feature {
    bindings = types.list {
      element = activationBinding;
      maxItems = 256;
    };
  } [];
  activation = request activationFeature;

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
    capability_bounds = capabilityBounds;
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
    security_label = {
      type = types.optional (boundedString 4096);
      optional = true;
    };
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
  interpolatedConfigurationFragment = types.taggedUnion {
    tag = "kind";
    variants = {
      literal = types.record {
        fields = {
          kind = types.enum ["literal"];
          text = boundedString 1048576;
        };
      };
      execution-path = types.record {
        fields = {
          kind = types.enum ["execution-path"];
          value = types.deferredResult executionPath;
        };
      };
      credential-content = types.record {
        fields = {
          kind = types.enum ["credential-content"];
          resource = types.deferredResult types.resourceReference;
          path = types.deferredResult credentialPath;
        };
      };
    };
  };
  interpolatedConfigurationSource = types.record {
    fields = {
      kind = types.enum ["interpolated-text"];
      fragments = types.list {
        element = interpolatedConfigurationFragment;
        maxItems = 65536;
      };
      maximum_size_bytes = types.integer {
        minimum = 1;
        maximum = types.limits.maxDocumentBytes;
      };
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
      interpolated-text = interpolatedConfigurationSource;
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
      scope = types.enum ["configured-connectivity" "default-route" "local-connectivity" "stack-prepared"];
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
  filesystemReadiness = types.record {
    fields.scope = types.enum ["local-filesystems"];
  };
  filesystemReadinessObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.filesystem-readiness-observation/v1"];
      expected = filesystemReadiness;
      state = types.enum ["configuring" "degraded" "failed" "ready" "unknown"];
    };
  };

  kernelModuleNames = types.list {
    element = localKey;
    maxItems = 256;
  };
  kernelModules = types.record {
    fields = {
      modules = kernelModuleNames;
      required = types.boolean;
    };
  };
  kernelModulesObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.kernel-modules-observation/v1"];
      expected = kernelModules;
      loaded = kernelModuleNames;
      unavailable = kernelModuleNames;
      state = types.enum ["absent" "failed" "partial" "ready" "unknown"];
    };
  };

  calendarSchedule = types.record {
    fields = {
      kind = types.enum ["calendar"];
      expression = boundedString 4096;
    };
  };
  intervalSchedule = types.record {
    fields = {
      kind = types.enum ["interval"];
      initial_delay_millis = durationMillis;
      interval_millis = positiveDurationMillis;
    };
  };
  schedule = types.taggedUnion {
    tag = "kind";
    variants = {
      calendar = calendarSchedule;
      interval = intervalSchedule;
    };
  };
  scheduledActivation = types.record {
    fields = {
      name = localKey;
      enabled = types.boolean;
      schedule = schedule;
      persistent = types.boolean;
      randomized_delay_millis = durationMillis;
    };
  };

  watchedPath = types.record {
    fields = {
      path = types.deferredResult executionPath;
      event = types.enum ["changed" "created" "directory-not-empty" "exists" "modified"];
    };
  };
  pathActivation = types.record {
    fields = {
      name = localKey;
      enabled = types.boolean;
      paths = types.list {
        element = watchedPath;
        maxItems = 256;
      };
    };
  };

  mountResource = types.record {
    fields = {
      name = localKey;
      enabled = types.boolean;
      source = types.deferredResult storagePath;
      destination = types.deferredResult executionPath;
      filesystem = {
        type = types.optional localKey;
        optional = true;
      };
      options = types.list {
        element = boundedString 1024;
        maxItems = 256;
      };
      timeout_millis = {
        type = types.optional positiveDurationMillis;
        optional = true;
      };
    };
  };
  automountResource = types.record {
    fields = {
      name = localKey;
      enabled = types.boolean;
      destination = types.deferredResult executionPath;
      idle_timeout_millis = {
        type = types.optional positiveDurationMillis;
        optional = true;
      };
    };
  };
  swapResource = types.record {
    fields = {
      name = localKey;
      enabled = types.boolean;
      source = types.deferredResult storagePath;
      priority = {
        type = types.optional (types.integer {
          minimum = -1;
          maximum = 32767;
        });
        optional = true;
      };
    };
  };
  activationGroup = types.record {
    fields = {
      name = localKey;
      enabled = types.boolean;
      description = boundedString 1024;
      members = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 256;
      };
    };
  };
  devicePresence = types.record {
    fields = {
      name = localKey;
      device = types.deferredResult deviceNode;
      timeout_millis = {
        type = types.optional positiveDurationMillis;
        optional = true;
      };
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
        relative_path = {
          type = types.optional types.relativePath;
          optional = true;
        };
      };
  };
  storageAllocation = types.record {
    fields = {
      name = localKey;
      purpose = types.enum ["cache" "logs" "runtime" "state" "temporary"];
      mode = types.fileMode;
      requested_path = {
        type = types.optional (types.deferredResult storagePath);
        optional = true;
      };
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
    requested_id = {
      type = types.integer {
        minimum = 1;
        maximum = 4294967294;
      };
      optional = true;
    };
  };
  principalResolution = types.record {
    fields =
      identityResolutionFields
      // {
        description = {
          type = boundedString 1024;
          optional = true;
        };
        home_directory = {
          type = types.deferredResult executionPath;
          optional = true;
        };
        login_access = {
          type = types.enum ["disabled" "enabled"];
          optional = true;
        };
        primary_group = {
          type = types.deferredResult groupName;
          optional = true;
        };
        supplementary_groups = {
          type = types.list {
            element = types.deferredResult groupName;
            maxItems = 256;
          };
          optional = true;
        };
      };
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
    scheduledActivation =
      producerObservation
      (types.enum ["aos.ability.scheduled-activation-observation/v1"])
      scheduledActivation
      types.resourceReference;
    pathActivation =
      producerObservation
      (types.enum ["aos.ability.path-activation-observation/v1"])
      pathActivation
      types.resourceReference;
    mountResource =
      producerObservation
      (types.enum ["aos.ability.mount-resource-observation/v1"])
      mountResource
      types.resourceReference;
    automountResource =
      producerObservation
      (types.enum ["aos.ability.automount-resource-observation/v1"])
      automountResource
      types.resourceReference;
    swapResource =
      producerObservation
      (types.enum ["aos.ability.swap-resource-observation/v1"])
      swapResource
      types.resourceReference;
    activationGroup =
      producerObservation
      (types.enum ["aos.ability.activation-group-observation/v1"])
      activationGroup
      types.resourceReference;
    devicePresence =
      producerObservation
      (types.enum ["aos.ability.device-presence-observation/v1"])
      devicePresence
      deviceNode;
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
        conditions = {
          type = types.optional conditionsFeature;
          optional = true;
        };
        instantiation = {
          type = types.optional instantiationFeature;
          optional = true;
        };
        supervision = {
          type = types.optional supervisionFeature;
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
        termination = {
          type = types.optional terminationFeature;
          optional = true;
        };
        watchdog = {
          type = types.optional watchdogFeature;
          optional = true;
        };
        start_policy = {
          type = types.optional startPolicyFeature;
          optional = true;
        };
        failure_policy = {
          type = types.optional failurePolicyFeature;
          optional = true;
        };
        scheduling = {
          type = types.optional schedulingFeature;
          optional = true;
        };
        resources = {
          type = types.optional resourcesFeature;
          optional = true;
        };
        environment = {
          type = types.optional environmentFeature;
          optional = true;
        };
        directories = {
          type = types.optional directoriesFeature;
          optional = true;
        };
        activation = {
          type = types.optional activationFeature;
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
    conditions = observationFor "conditions" conditions featureState {};
    instantiation = observationFor "instantiation" instantiation featureState {};
    supervision = observationFor "supervision" supervision featureState {};
    readiness = observationFor "readiness" readiness lifecycleState {};
    reload = observationFor "reload" reload featureState {available = types.boolean;};
    termination = observationFor "termination" termination featureState {};
    watchdog = observationFor "watchdog" watchdog featureState {};
    startPolicy = observationFor "start-policy" startPolicy featureState {};
    failurePolicy = observationFor "failure-policy" failurePolicy featureState {};
    scheduling = observationFor "scheduling" scheduling featureState {};
    resources = observationFor "resources" resources featureState {};
    environment = observationFor "environment" environment featureState {};
    directories = observationFor "directories" directories featureState {};
    activation = observationFor "activation" activation featureState {};
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
    resourceLimit
    capabilityBounds
    configurationMaterialization
    configurationMaterializationObservation
    networkReadiness
    networkReadinessObservation
    filesystemReadiness
    filesystemReadinessObservation
    kernelModules
    kernelModulesObservation
    credentialDelivery
    storageView
    storageAllocation
    hostPathView
    deviceView
    rootDirectoryView
    principalResolution
    groupResolution
    scheduledActivation
    pathActivation
    mountResource
    automountResource
    swapResource
    activationGroup
    devicePresence
    producerObservations
    structuredConfigurationSource
    structuredDocumentValid
    lifecycle
    dependencies
    conditions
    instantiation
    supervision
    readiness
    reload
    termination
    watchdog
    startPolicy
    failurePolicy
    scheduling
    resources
    environment
    directories
    activation
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
