##! Native reusable service feature schemas, composed from ordinary option types.
{lib}: let
  optionFor = name: definition: let
    spec =
      if definition ? type
      then definition
      else {type = definition;};
  in
    lib.mkOption ({
        inherit (spec) type;
        description = "Service ${name} setting.";
      }
      // lib.optionalAttrs (spec ? default) {inherit (spec) default;}
      // lib.optionalAttrs (!(spec ? default) && (spec.optional or false)) {default = null;});

  record = {
    fields,
    optional ? [],
  }:
    lib.types.submodule {
      _module.strict = true;
      options = builtins.mapAttrs (name: value:
        optionFor name (
          if builtins.elem name optional
          then {
            type = lib.types.nullOr (
              if value ? type
              then value.type
              else value
            );
            default = null;
          }
          else value
        ))
      fields;
    };

  string = {
    maxLength,
    syntax ? null,
  }:
    lib.types.strWith {
      inherit maxLength;
      pattern =
        if syntax == "local-key-v1"
        then "[A-Za-z0-9._-]+"
        else null;
    };
  integer = {
    minimum ? null,
    maximum ? null,
  }:
    lib.types.ints.between minimum maximum;
  list = {
    element,
    maxItems,
    unique ? false,
    canonicalOrder ? false,
  }: let
    bounded = lib.types.listWith {
      elemType = element;
      inherit maxItems unique canonicalOrder;
    };
    elements = lib.types.listOf element;
  in
    bounded
    // lib.optionalAttrs canonicalOrder {
      # These fields denote sets. Resolve ordinary module definitions first,
      # then canonicalize identities; authored order and repeated definitions
      # cannot change the resulting dependency graph. The wire schema remains
      # bounded, unique, and canonical for independently submitted payloads.
      merge = location: definitions: let
        merged = elements.merge location definitions;
        byIdentity = builtins.listToAttrs (builtins.map (value: {
            name = builtins.unsafeDiscardStringContext (builtins.toJSON value);
            inherit value;
          })
          merged);
        normalized = builtins.map (identity: byIdentity.${identity}) (builtins.attrNames byIdentity);
      in
        if bounded.check normalized
        then normalized
        else throw "Service set '${builtins.concatStringsSep "." location}' violates its declared bounds.";
    };
  map = {
    value,
    maxEntries,
    keyMaxLength,
    keySyntax ? null,
  }:
    lib.types.attrsWith {
      elemType = value;
      inherit maxEntries keyMaxLength keySyntax;
    };
  union = {
    tag,
    variants,
  }:
    lib.types.taggedUnion tag variants;

  boundedString = maxLength:
    string {
      inherit maxLength;
      syntax = null;
    };
  localKey = string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  localKeys = list {
    element = localKey;
    maxItems = 256;
  };
  executionPath = lib.types.str;
  configurationPath = executionPath;
  credentialPath = executionPath;
  storagePath = executionPath;
  hostPath = executionPath;
  deviceNode = executionPath;
  rootDirectoryPath = executionPath;
  principalName = lib.types.str;
  groupName = lib.types.str;
  fileMode = lib.types.strWith {
    maxLength = 4;
    pattern = "[0-7]{3,4}";
  };
  restartToken = boundedString 1024;
  signalName = boundedString 64;
  statusCode = integer {
    minimum = 0;
    maximum = 255;
  };
  durationMillis = integer {
    minimum = 0;
    maximum = 9007199254740991;
  };
  positiveDurationMillis = integer {
    minimum = 1;
    maximum = 9007199254740991;
  };
  resourceLimit = union {
    tag = "kind";
    variants = {
      maximum = record {
        fields = {
          kind = lib.types.enum ["maximum"];
          value = integer {
            minimum = 0;
            maximum = 9007199254740991;
          };
        };
      };
      unbounded = record {
        fields.kind = lib.types.enum ["unbounded"];
      };
    };
  };
  command = record {
    fields = {
      executable = record {
        fields = {
          path = lib.types.deferred lib.types.str;
          arguments = lib.types.listOf (lib.types.deferred lib.types.str);
        };
      };
      ignore_failure = lib.types.bool;
    };
  };
  commands = list {
    element = command;
    maxItems = 64;
  };
  environmentFile = record {
    fields = {
      source = lib.types.deferred configurationPath;
      optional = lib.types.bool;
    };
  };
  environmentFiles = list {
    element = environmentFile;
    maxItems = 64;
  };
  environmentVariable = lib.types.deferred lib.types.str;
  environmentVariables = map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 256;
    value = environmentVariable;
  };

  serviceBaseFields = {
    service = localKey;
    enabled = lib.types.bool;
    activation_owner = {
      type = lib.types.enum ["ability" "image" "manager"];
      optional = true;
    };
  };
  feature = fields: optional:
    (record {
      inherit fields;
      inherit optional;
    })
    // {
      _serviceFeatureFields = fields;
      _serviceFeatureOptional = optional;
    };
  request = featureType:
    record {
      fields = serviceBaseFields // featureType._serviceFeatureFields;
      optional = featureType._serviceFeatureOptional;
    };

  lifecycleFeature = feature {
    description = boundedString 1024;
    execution_model = lib.types.enum ["foreground" "forking" "oneshot"];
    working_directory = {
      type = lib.types.nullOr (lib.types.deferred executionPath);
      optional = true;
    };
    environment_files = environmentFiles;
    condition = commands;
    pre_start = commands;
    start = commands;
    post_start = commands;
    stop = commands;
    post_stop = commands;
    removal_guard = {
      type = commands;
      default = [];
    };
    restart = lib.types.enum ["always" "never" "on-failure"];
    restart_token = {
      type = lib.types.nullOr restartToken;
      optional = true;
    };
    restart_delay_millis = integer {
      minimum = 0;
      maximum = 86400000;
    };
    configuration_change_action = {
      type = lib.types.enum ["none" "reload" "restart"];
      default = "restart";
    };
    remain_after_exit = lib.types.bool;
    start_timeout_millis = positiveDurationMillis;
    start_timeout_unbounded = {
      type = lib.types.bool;
      default = false;
    };
    stop_timeout_millis = positiveDurationMillis;
    stop_timeout_unbounded = {
      type = lib.types.bool;
      default = false;
    };
  } [];
  lifecycle = request lifecycleFeature;
  templateDefinition = record {
    fields =
      {
        service = localKey;
        inherit (serviceBaseFields) activation_owner;
      }
      // lifecycleFeature._serviceFeatureFields;
    optional = lifecycleFeature._serviceFeatureOptional;
  };
  dependenciesFeature = feature {
    prerequisites = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      default = [];
    };
    after = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    before = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    requires = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    wants = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    requisite = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    conflicts = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    binds_to = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    part_of = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    upholds = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    required_by = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    wanted_by = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    required_mounts = {
      type = list {
        element = lib.types.deferred lib.types.str;
        maxItems = 256;
      };
      default = [];
    };
    implicit_dependencies = {
      type = lib.types.bool;
      default = true;
    };
  } [];
  dependencies = request dependenciesFeature;

  pathCondition = record {
    fields = {
      kind = lib.types.enum ["path"];
      predicate = lib.types.enum ["exists" "is-directory" "is-mount-point" "is-nonempty"];
      path = lib.types.deferred executionPath;
      negated = lib.types.bool;
    };
  };
  kernelArgumentCondition = record {
    fields = {
      kind = lib.types.enum ["kernel-argument"];
      argument = boundedString 4096;
      negated = lib.types.bool;
    };
  };
  mandatoryAccessControlCondition = record {
    fields = {
      kind = lib.types.enum ["mandatory-access-control"];
      state = lib.types.enum ["available" "enforcing"];
      negated = lib.types.bool;
    };
  };
  condition = union {
    tag = "kind";
    variants = {
      path = pathCondition;
      kernel-argument = kernelArgumentCondition;
      mandatory-access-control = mandatoryAccessControlCondition;
    };
  };
  conditionsFeature = feature {
    all = list {
      element = condition;
      maxItems = 256;
    };
  } [];
  conditions = request conditionsFeature;

  instantiationSelection = union {
    tag = "kind";
    variants = {
      singleton = record {
        fields.kind = lib.types.enum ["singleton"];
      };
      template = record {
        fields = {
          kind = lib.types.enum ["template"];
          template = localKey;
        };
      };
      instance = record {
        fields = {
          kind = lib.types.enum ["instance"];
          instance = boundedString 1024;
          template_resource = lib.types.deferred lib.types.str;
        };
      };
    };
  };
  instantiationFeature = feature {selection = instantiationSelection;} [];
  instantiation = request instantiationFeature;

  managerIdentityFeature = feature {
    name = localKey;
    aliases = localKeys;
  } [];
  managerIdentity = request managerIdentityFeature;

  supervisionFeature = feature {
    startup_protocol = lib.types.enum ["process" "notification" "bus-name"];
    notification_access = lib.types.enum ["none" "main-process" "all-processes"];
    bus_name = {
      type = lib.types.nullOr (boundedString 255);
      optional = true;
    };
  } [];
  supervision = request supervisionFeature;
  readinessFeature = feature {
    mechanism = lib.types.enum ["process-running" "process-signal" "socket-accepting" "successful-exit"];
    signal_scope = lib.types.enum ["all-processes" "main-process" "none"];
    timeout_millis = integer {
      minimum = 1;
      maximum = 86400000;
    };
  } [];
  readiness = request readinessFeature;
  reloadFeature = feature {
    strategy = lib.types.enum ["command" "restart" "signal" "unsupported"];
    commands = commands;
    signal = {
      type = lib.types.nullOr signalName;
      optional = true;
    };
    completion = {
      type = lib.types.nullOr (lib.types.enum ["command-exit" "notification"]);
      optional = true;
    };
  } [];
  reload = request reloadFeature;

  terminationFeature = feature {
    signal = signalName;
    final_signal = {
      type = lib.types.nullOr signalName;
      optional = true;
    };
    process_id_file = {
      type = lib.types.nullOr (lib.types.deferred executionPath);
      optional = true;
    };
    send_to_all_processes = lib.types.bool;
  } [];
  termination = request terminationFeature;

  watchdogFeature = feature {
    timeout_millis = positiveDurationMillis;
    action = lib.types.enum ["restart" "stop"];
  } [];
  watchdog = request watchdogFeature;

  startPolicyFeature = feature {
    accepted_exit_statuses = list {
      element = statusCode;
      maxItems = 256;
    };
    restart_preventing_exit_statuses = list {
      element = statusCode;
      maxItems = 256;
    };
    rate_interval_millis = {
      type = lib.types.nullOr positiveDurationMillis;
      optional = true;
    };
    rate_burst = {
      type = lib.types.nullOr (integer {
        minimum = 1;
        maximum = 4294967295;
      });
      optional = true;
    };
  } [];
  startPolicy = request startPolicyFeature;

  failurePolicyFeature = feature {
    handlers = list {
      element = lib.types.deferred lib.types.str;
      maxItems = 256;
    };
    dispatch = lib.types.enum ["enqueue" "isolate-active-goal" "replace-active-goal"];
  } [];
  failurePolicy = request failurePolicyFeature;

  concurrencyFeature = feature {
    group = localKey;
    conflict = lib.types.enum ["reject"];
  } [];
  concurrency = request concurrencyFeature;

  schedulingFeature = feature {
    cpu_policy = {
      type = lib.types.nullOr (lib.types.enum ["other" "batch" "idle"]);
      default = null;
    };
    nice = integer {
      minimum = -20;
      maximum = 19;
    };
    io_class = lib.types.enum ["best-effort" "idle" "realtime"];
    io_priority = integer {
      minimum = 0;
      maximum = 7;
    };
  } [];
  scheduling = request schedulingFeature;

  resourcesFeature =
    feature {
      resource_group = {
        type = lib.types.nullOr (lib.types.strMatching "aos-pkg-[a-z0-9-]+");
        default = null;
      };
      open_files = resourceLimit;
      processes = resourceLimit;
      tasks = resourceLimit;
      locked_memory_bytes = resourceLimit;
      memory_high_bytes = resourceLimit;
      memory_max_bytes = resourceLimit;
      memory_swap_max_bytes = resourceLimit;
      oom_policy = lib.types.enum ["continue" "stop" "kill"];
    } [
      "open_files"
      "processes"
      "tasks"
      "locked_memory_bytes"
      "memory_high_bytes"
      "memory_max_bytes"
      "memory_swap_max_bytes"
      "oom_policy"
    ];
  resources = request resourcesFeature;

  environmentFeature = feature {
    variables = environmentVariables;
    search_path = list {
      element = lib.types.str;
      maxItems = 256;
    };
  } [];
  environment = request environmentFeature;

  managedDirectory = record {
    fields = {
      path = lib.types.str;
      purpose = lib.types.enum ["cache" "configuration" "logs" "runtime" "state"];
      mode = fileMode;
      retention = lib.types.enum ["service-lifetime" "restart" "persistent"];
      owner = {
        type = lib.types.nullOr (lib.types.deferred principalName);
        optional = true;
      };
      group = {
        type = lib.types.nullOr (lib.types.deferred groupName);
        optional = true;
      };
    };
  };
  directoriesFeature = feature {
    managed = list {
      element = managedDirectory;
      maxItems = 256;
    };
  } [];
  directories = request directoriesFeature;

  activationBindingBase = {
    name = localKey;
    resource = lib.types.deferred lib.types.str;
  };
  activationBinding = union {
    tag = "relationship";
    variants = {
      service-depends-on-resource = record {
        fields =
          activationBindingBase
          // {
            relationship = lib.types.enum ["service-depends-on-resource"];
          };
      };
      service-member-of-resource = record {
        fields =
          activationBindingBase
          // {
            relationship = lib.types.enum ["service-member-of-resource"];
          };
      };
      resource-triggers-service = record {
        fields =
          activationBindingBase
          // {
            relationship = lib.types.enum ["resource-triggers-service"];
          };
      };
    };
  };
  activationFeature = feature {
    bindings = list {
      element = activationBinding;
      maxItems = 256;
    };
  } [];
  activation = request activationFeature;

  credentialView = record {
    fields = {
      name = localKey;
      reference = lib.types.deferred credentialPath;
      encrypted = lib.types.bool;
      optional = lib.types.bool;
      environment_variable = {
        type = lib.types.nullOr localKey;
        optional = true;
      };
    };
  };
  credentialsFeature = feature {
    views = list {
      element = credentialView;
      maxItems = 256;
    };
  } [];
  credentials = request credentialsFeature;

  configurationView = record {
    fields = {
      name = localKey;
      source = lib.types.deferred configurationPath;
      optional = lib.types.bool;
    };
  };
  configurationFeature = feature {
    views = list {
      element = configurationView;
      maxItems = 256;
    };
  } [];
  configuration = request configurationFeature;

  storageMount = record {
    fields = {
      name = localKey;
      source = lib.types.deferred storagePath;
      access = lib.types.enum ["read-only" "read-write"];
      ownership = {
        type = lib.types.enum ["provider" "service-identity"];
        default = "provider";
      };
    };
  };
  storageFeature = feature {
    mounts = list {
      element = storageMount;
      maxItems = 256;
    };
  } [];
  storage = request storageFeature;

  unixSocket = record {
    fields = {
      kind = lib.types.enum ["unix"];
      path = lib.types.deferred executionPath;
    };
  };
  networkSocket = record {
    fields = {
      kind = lib.types.enum ["network"];
      address = boundedString 255;
      port = integer {
        minimum = 1;
        maximum = 65535;
      };
      transport = lib.types.enum ["tcp" "udp"];
    };
  };
  socketEndpoint = union {
    tag = "kind";
    variants = {
      network = networkSocket;
      unix = unixSocket;
    };
  };
  socket = record {
    fields = {
      name = localKey;
      manager_name = {
        type = lib.types.nullOr localKey;
        optional = true;
      };
      enabled = {
        type = lib.types.bool;
        default = true;
      };
      endpoints = list {
        element = socketEndpoint;
        maxItems = 64;
      };
      directory_mode = {
        type = fileMode;
        default = "0755";
      };
      mode = {
        type = fileMode;
        default = "0666";
      };
      owner = {
        type = lib.types.nullOr (lib.types.deferred principalName);
        optional = true;
      };
      group = {
        type = lib.types.nullOr (lib.types.deferred groupName);
        optional = true;
      };
      remove_on_stop = {
        type = lib.types.bool;
        default = false;
      };
      prerequisites = {
        type = list {
          element = lib.types.deferred lib.types.str;
          maxItems = 256;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      after = {
        type = list {
          element = localKey;
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      binds_to = {
        type = list {
          element = localKey;
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
    };
  };
  socketServiceDependencies = record {
    fields = {
      after = {
        type = list {
          element = localKey;
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      binds_to = {
        type = list {
          element = localKey;
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      requires = {
        type = list {
          element = localKey;
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      wants = {
        type = list {
          element = localKey;
          maxItems = 64;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
    };
  };
  socketActivationFeature = feature {
    sockets = list {
      element = socket;
      maxItems = 64;
    };
    service_dependencies = {
      type = socketServiceDependencies;
      default = {};
    };
  } [];
  socketActivation = request socketActivationFeature;

  loggingFeature = feature {
    standard_output = lib.types.enum ["console" "discard" "inherit" "structured" "structured-and-console"];
    standard_error = lib.types.enum ["console" "discard" "inherit" "structured" "structured-and-console"];
    namespace = {
      type = lib.types.nullOr localKey;
      optional = true;
    };
    directories = localKeys;
    directory_mode = fileMode;
  } [];
  logging = request loggingFeature;

  terminalFeature = feature {
    device = deviceNode;
    reset = lib.types.bool;
    hangup = lib.types.bool;
    deallocate = lib.types.bool;
    send_hangup_on_stop = lib.types.bool;
    start_when_idle = lib.types.bool;
    session_identifier = {
      type = lib.types.nullOr localKey;
      optional = true;
    };
  } ["session_identifier"];
  terminal = request terminalFeature;

  identityFeature = feature {
    principal = {
      type = lib.types.nullOr (lib.types.deferred principalName);
      optional = true;
    };
    primary_group = {
      type = lib.types.nullOr (lib.types.deferred groupName);
      optional = true;
    };
    supplementary_groups = list {
      element = lib.types.deferred groupName;
      maxItems = 256;
    };
    ephemeral = lib.types.bool;
    file_creation_mask = fileMode;
  } [];
  identity = request identityFeature;

  hostPathAccess = record {
    fields = {
      source = lib.types.deferred hostPath;
      mode = lib.types.enum ["read-only" "read-write"];
    };
  };
  deviceAccess = record {
    fields = {
      source = lib.types.deferred deviceNode;
      read = lib.types.bool;
      write = lib.types.bool;
      create_node = lib.types.bool;
    };
  };
  isolationFeature = feature {
    privilege = lib.types.enum ["privileged" "unprivileged"];
    filesystem = lib.types.enum ["host" "private" "read-only-software" "read-only-system"];
    home_access = {
      type = lib.types.enum ["host" "read-only" "inaccessible"];
      default = "host";
    };
    network = lib.types.enum ["host" "none" "private"];
    process_visibility = lib.types.enum ["host" "private"];
    termination_scope = lib.types.enum ["all-processes" "main-process" "mixed"];
    temporary_directory = lib.types.enum ["disconnected" "private" "shared"];
    devices = list {
      element = deviceAccess;
      maxItems = 256;
    };
    temporary_filesystems = {
      type = list {
        element = record {
          fields = {
            path = lib.types.deferred hostPath;
            read_only = lib.types.bool;
          };
        };
        maxItems = 256;
      };
      default = [];
    };
    host_paths = list {
      element = hostPathAccess;
      maxItems = 256;
    };
    permit_core_dumps = lib.types.bool;
    root_directory = {
      type = lib.types.nullOr (lib.types.deferred rootDirectoryPath);
      optional = true;
    };
  } [];
  isolation = request isolationFeature;

  serviceDeclarationFields =
    serviceBaseFields
    // {
      lifecycle = lifecycleFeature;
      dependencies = {
        type = lib.types.nullOr dependenciesFeature;
        optional = true;
      };
      conditions = {
        type = lib.types.nullOr conditionsFeature;
        optional = true;
      };
      instantiation = {
        type = lib.types.nullOr instantiationSelection;
        optional = true;
      };
      manager_identity = {
        type = lib.types.nullOr managerIdentityFeature;
        optional = true;
      };
      supervision = {
        type = lib.types.nullOr supervisionFeature;
        optional = true;
      };
      readiness = {
        type = lib.types.nullOr readinessFeature;
        optional = true;
      };
      reload = {
        type = lib.types.nullOr reloadFeature;
        optional = true;
      };
      termination = {
        type = lib.types.nullOr terminationFeature;
        optional = true;
      };
      watchdog = {
        type = lib.types.nullOr watchdogFeature;
        optional = true;
      };
      start_policy = {
        type = lib.types.nullOr startPolicyFeature;
        optional = true;
      };
      failure_policy = {
        type = lib.types.nullOr failurePolicyFeature;
        optional = true;
      };
      concurrency = {
        type = lib.types.nullOr concurrencyFeature;
        optional = true;
      };
      scheduling = {
        type = lib.types.nullOr schedulingFeature;
        optional = true;
      };
      resources = {
        type = lib.types.nullOr resourcesFeature;
        optional = true;
      };
      environment = {
        type = lib.types.nullOr environmentFeature;
        optional = true;
      };
      directories = {
        type = lib.types.nullOr directoriesFeature;
        optional = true;
      };
      activation = {
        type = lib.types.nullOr activationFeature;
        optional = true;
      };
      credentials = {
        type = lib.types.nullOr credentialsFeature;
        optional = true;
      };
      configuration = {
        type = lib.types.nullOr configurationFeature;
        optional = true;
      };
      storage = {
        type = lib.types.nullOr storageFeature;
        optional = true;
      };
      socket_activation = {
        type = lib.types.nullOr socketActivationFeature;
        optional = true;
      };
      logging = {
        type = lib.types.nullOr loggingFeature;
        optional = true;
      };
      terminal = {
        type = lib.types.nullOr terminalFeature;
        optional = true;
      };
      identity = {
        type = lib.types.nullOr identityFeature;
        optional = true;
      };
      isolation = {
        type = lib.types.nullOr isolationFeature;
        optional = true;
      };
    };
in {
  inherit serviceDeclarationFields optionFor record;
}
