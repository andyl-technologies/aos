##! Package-owned PostgreSQL options and provider-neutral service declarations.
{
  config,
  lib,
  ...
}: let
  cfg = config.postgresql;
  inherit (lib.abilities) pathWithin resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  boundedText = maximum:
    abilityTypes.string {
      maxLength = maximum;
      syntax = null;
    };
  checkedString = name: description: pattern:
    abilityTypes.refined {
      inherit name description;
      type = abilityTypes.runtimeString;
      constraints = [
        {
          kind = "string-pattern";
          pattern = pattern;
        }
      ];
    };
  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  nonNegativeInt = abilityTypes.integer {
    minimum = 0;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  nonEmptyLine = abilityTypes.refined {
    name = "PostgreSQL non-empty line";
    description = "a non-empty PostgreSQL value without line breaks";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
      {
        kind = "string-excludes";
        classes = ["line-break"];
      }
    ];
  };
  identifier =
    checkedString
    "PostgreSQL identifier"
    "a PostgreSQL identifier beginning with a letter or underscore"
    "[A-Za-z_][A-Za-z0-9_$-]*";
  address =
    checkedString
    "PostgreSQL address"
    "a PostgreSQL host or address without commas, quotes, or whitespace"
    "[^,'[:space:]]+";
  memorySize =
    checkedString
    "PostgreSQL memory size"
    "a positive PostgreSQL memory size with an explicit unit"
    "[1-9][0-9]*(B|kB|MB|GB|TB)";
  settingName =
    checkedString
    "PostgreSQL setting name"
    "a lowercase PostgreSQL parameter name"
    "[a-z][a-z0-9_]*";
  settingString = abilityTypes.refined {
    name = "PostgreSQL setting value";
    description = "a PostgreSQL setting value without line breaks";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-excludes";
        classes = ["line-break"];
      }
    ];
  };
  settingValue = abilityTypes.disjointUnion [
    abilityTypes.boolean
    (abilityTypes.integer {
      minimum = -abilityTypes.limits.maxSafeInteger;
      maximum = abilityTypes.limits.maxSafeInteger;
    })
    settingString
  ];
  settingsType = abilityTypes.map {
    keyMaxLength = 63;
    keySyntax = null;
    maxEntries = 1024;
    value = settingValue;
  };
  addressList = abilityTypes.list {
    element = address;
    maxItems = 64;
    unique = false;
    canonicalOrder = false;
  };
  hbaSelector =
    checkedString
    "PostgreSQL HBA selector"
    "a PostgreSQL database, role, or HBA keyword"
    "[A-Za-z0-9_.+-]+";
  hbaSelectorList = abilityTypes.list {
    element = hbaSelector;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  credentialReference = serviceTypes.credentialReference;
  endpointType = abilityTypes.record {
    fields = {
      host = address;
      port = port;
    };
    optional = ["port"];
  };
  hbaRuleType = abilityTypes.record {
    fields = {
      type = abilityTypes.enum ["local" "host" "hostssl" "hostnossl"];
      databases = hbaSelectorList;
      users = hbaSelectorList;
      address = abilityTypes.optional nonEmptyLine;
      method = abilityTypes.enum ["cert" "md5" "peer" "reject" "scram-sha-256" "trust"];
    };
    optional = ["type" "databases" "users" "address" "method"];
  };
  hbaRules = abilityTypes.list {
    element = hbaRuleType;
    maxItems = 1024;
    unique = false;
    canonicalOrder = false;
  };

  normalizeEndpoint = endpoint:
    if endpoint == null
    then null
    else {
      inherit (endpoint) host;
      port = endpoint.port or 5432;
    };
  normalizeHbaRule = rule: {
    type = rule.type or "host";
    databases = rule.databases or ["all"];
    users = rule.users or ["all"];
    address = rule.address or null;
    method = rule.method or "scram-sha-256";
  };
  bootstrapPassword = cfg.bootstrap.password;
  replicationPassfile = cfg.replication.passfile;
  tlsCertificate = cfg.tls.certificate;
  tlsPrivateKey = cfg.tls.privateKey;
  tlsCa = cfg.tls.ca;
  primary = normalizeEndpoint cfg.replication.primary;
  hba = builtins.map normalizeHbaRule cfg.authentication.rules;

  quote = value: "'${builtins.replaceStrings ["'"] ["''"] value}'";
  renderSettingValue = value:
    if builtins.isBool value
    then
      if value
      then "on"
      else "off"
    else if builtins.isInt value
    then toString value
    else quote value;
  renderSetting = name: value: "${name} = ${renderSettingValue value}\n";
  renderHbaRule = rule:
    lib.concatStringsSep " " (
      [
        rule.type
        (lib.concatStringsSep "," rule.databases)
        (lib.concatStringsSep "," rule.users)
      ]
      ++ lib.optional (rule.type != "local") rule.address
      ++ [rule.method]
    );
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/postgresql-control";
      inherit arguments;
    };
    ignore_failure = false;
  };
  runtimeSearchPath =
    builtins.map
    (package: lib.abilities.packageOutput {inherit package;})
    ["self" "bash" "coreutils"];

  configuredCredentials =
    lib.optional (cfg.topology != "standby" && serviceManagement.credentialReferenceConfigured bootstrapPassword) {
      name = "bootstrap-superuser-password";
      reference = bootstrapPassword;
    }
    ++ lib.optional (cfg.topology == "standby" && serviceManagement.credentialReferenceConfigured replicationPassfile) {
      name = "replication-passfile";
      reference = replicationPassfile;
    }
    ++ lib.optionals cfg.tls.enable (
      [
        {
          name = "tls-certificate";
          reference = tlsCertificate;
        }
        {
          name = "tls-private-key";
          reference = tlsPrivateKey;
        }
      ]
      ++ lib.optional (serviceManagement.credentialReferenceConfigured tlsCa) {
        name = "tls-ca";
        reference = tlsCa;
      }
    );
  credentialRequests = serviceManagement.forCredentialReferences {
    consumerInstance = "postgresql";
    references =
      builtins.map (credential: {
        key = "credential-${credential.name}";
        inherit (credential) name reference;
      })
      configuredCredentials;
  };
  storage = serviceManagement.forProducers {
    consumerInstance = "postgresql";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    producers = [
      {
        key = "state-storage";
        parameters = {
          name = "state";
          purpose = "state";
          mode = "0700";
        };
      }
    ];
  };
  runtimeStorage = serviceManagement.forProducer {
    consumerInstance = "postgresql";
    key = "runtime-storage";
    interface = serviceManagement.interfaces.storageAllocation;
    parameters = {
      name = "runtime";
      purpose = "runtime";
      mode = "0755";
    };
  };
  networkReadiness = serviceManagement.forProducer {
    consumerInstance = "postgresql";
    key = "network-readiness";
    interface = serviceManagement.interfaces.networkReadiness;
    parameters = {
      scope = "configured-connectivity";
      address_families = ["ipv4" "ipv6"];
    };
  };

  stateRuntimePath = resultOf "state-storage" "planned-path";
  runtimeRuntimePath = resultOf "runtime-storage" "planned-path";
  statePlannedPath = resultOf "state-storage" "planned-path";
  runtimePlannedPath = resultOf "runtime-storage" "planned-path";
  dataRuntimePath = pathWithin {
    base = stateRuntimePath;
    relativePath = "data";
  };
  socketRuntimePath = runtimeRuntimePath;
  serverConfigurationPath = resultOf "server-configuration" "planned-path";
  hbaConfigurationPath = resultOf "hba-configuration" "planned-path";
  credentialPath = name: resultOf "credential-${name}" "credential-path";

  hbaConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "postgresql";
    declaration = {
      name = "hba-configuration";
      source = {
        kind = "inline-text";
        content = ''
          # Generated by the PostgreSQL package module. Do not edit.
          ${lib.concatStringsSep "\n" (builtins.map renderHbaRule hba)}
        '';
      };
      mode = "0444";
    };
  };
  primaryConnInfoFragments =
    if cfg.topology != "standby"
    then []
    else [
      (literal "primary_conninfo = '")
      (literal "host=${primary.host} port=${toString primary.port} user=${cfg.replication.user} application_name=${cfg.replication.applicationName} passfile=")
      (executionPath (credentialPath "replication-passfile"))
      (literal "'\n")
    ];
  tlsFragments =
    if !cfg.tls.enable
    then [(literal "ssl = off\n")]
    else
      [
        (literal "ssl = on\nssl_cert_file = '")
        (executionPath (credentialPath "tls-certificate"))
        (literal "'\nssl_key_file = '")
        (executionPath (credentialPath "tls-private-key"))
        (literal "'\n")
      ]
      ++ lib.optionals (serviceManagement.credentialReferenceConfigured tlsCa) [
        (literal "ssl_ca_file = '")
        (executionPath (credentialPath "tls-ca"))
        (literal "'\n")
      ];
  serverConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "postgresql";
    declaration = {
      name = "server-configuration";
      source = {
        kind = "interpolated-text";
        fragments =
          [
            (literal "# Generated by the PostgreSQL package module. Do not edit.\ndata_directory = '")
            (executionPath dataRuntimePath)
            (literal "'\nhba_file = '")
            (executionPath hbaConfigurationPath)
            (literal "'\nlisten_addresses = ${quote (lib.concatStringsSep "," cfg.listen.addresses)}\nport = ${toString cfg.listen.port}\nunix_socket_directories = '")
            (executionPath socketRuntimePath)
            (literal "'\ncluster_name = ${quote cfg.clusterName}\n\nmax_connections = ${toString cfg.resources.maxConnections}\nshared_buffers = ${quote cfg.resources.sharedBuffers}\nwork_mem = ${quote cfg.resources.workMem}\nmaintenance_work_mem = ${quote cfg.resources.maintenanceWorkMem}\n\nwal_level = ${cfg.replication.walLevel}\nmax_wal_senders = ${toString cfg.replication.maxWalSenders}\nmax_replication_slots = ${toString cfg.replication.maxReplicationSlots}\nhot_standby = ${
              if cfg.replication.hotStandby
              then "on"
              else "off"
            }\n")
          ]
          ++ primaryConnInfoFragments
          ++ lib.optionals (cfg.topology == "standby" && cfg.replication.slot != null) [
            (literal "primary_slot_name = ${quote cfg.replication.slot}\n")
          ]
          ++ tlsFragments
          ++ [
            (literal "ssl_min_protocol_version = ${quote cfg.tls.minimumProtocol}\nlogging_collector = off\nlog_destination = 'stderr'\n")
            (literal (lib.concatStringsSep "" (lib.mapAttrsToList renderSetting cfg.settings)))
          ];
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };

  commonStorage.mounts = [
    {
      name = "state";
      source = statePlannedPath;
      access = "read-write";
    }
    {
      name = "runtime";
      source = runtimePlannedPath;
      access = "read-write";
    }
  ];
  commonIdentity = {
    supplementary_groups = [];
    ephemeral = true;
    file_creation_mask = "0077";
  };
  commonIsolation = {
    privilege = "unprivileged";
    filesystem = "read-only-system";
    network = "host";
    process_visibility = "host";
    termination_scope = "all-processes";
    temporary_directory = "private";
    devices = [];
    host_paths = [];
    permit_core_dumps = false;
  };
  commonHardening = {
    allow_privilege_escalation = false;
    ambient_privileges = [];
    privilege_bounds = {
      kind = "restricted";
      privileges = [];
    };
    resource_control_delegation = false;
    resource_control_access = "read-only";
    device_access_scope = "shared";
    host_clock_mutation = false;
    host_name_mutation = false;
    operating_system_log_access = false;
    operating_system_extension_access = false;
    operating_system_tunable_access = false;
    lock_execution_personality = true;
    writable_executable_memory = false;
    isolation_domains = [];
    network_families = ["ipv4" "ipv6" "local"];
    memory_pressure_adjustment = 0;
    permit_realtime = false;
    permit_elevated_file_identity = false;
    process_visibility = "all";
    security_label = "aos-pkg-postgresql";
    operation_architectures = [];
    operation_allow = [];
    operation_deny = [];
    operation_profile = "system-service";
    isolated_identity_mapping = "none";
  };
  initializationCredential =
    if cfg.topology == "standby"
    then "replication-passfile"
    else "bootstrap-superuser-password";
  initializationCredentialMatches =
    builtins.filter
    (credential: credential.name == initializationCredential)
    configuredCredentials;
  initializationCredentialReference =
    if initializationCredentialMatches == []
    then null
    else (builtins.head initializationCredentialMatches).reference;
  initializationCredentialPath =
    if initializationCredentialReference == null
    then ""
    else credentialPath initializationCredential;
  prepareArguments = [
    "prepare"
    statePlannedPath
    serverConfigurationPath
    cfg.topology
    cfg.bootstrap.superuser
    initializationCredentialPath
    (
      if primary == null
      then ""
      else primary.host
    )
    (
      if primary == null
      then "5432"
      else toString primary.port
    )
    cfg.replication.user
    (
      if cfg.replication.slot == null
      then ""
      else cfg.replication.slot
    )
  ];
  initService = {
    policy.hardening = commonHardening;
    consumerInstance = "postgresql";
    service = "initialize";
    lifecycle = {
      description = "Initialize PostgreSQL database state";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command prepareArguments)];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "never";
      restart_delay_millis = 0;
      configuration_change_action = "restart";
      remain_after_exit = true;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [(resultOf "network-readiness" "resource")];
      before = [];
      requires = [];
      wants = [(resultOf "network-readiness" "resource")];
    };
    supervision = {
      startup_protocol = "process";
      notification_access = "none";
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    credentials.views = lib.optional (initializationCredentialReference != null) {
      name = initializationCredential;
      encrypted = initializationCredentialReference.encrypted;
      reference = initializationCredentialPath;
      optional = false;
    };
    configuration.views = [
      {
        name = "server";
        source = serverConfigurationPath;
        optional = false;
      }
    ];
    environment = {
      variables = {};
      search_path = runtimeSearchPath;
    };
    storage = commonStorage;
    identity = commonIdentity;
    isolation = commonIsolation;
  };
  mainCredentialNames =
    lib.optional (
      cfg.topology
      == "standby"
      && serviceManagement.credentialReferenceConfigured replicationPassfile
    ) "replication-passfile"
    ++ lib.optionals cfg.tls.enable (
      lib.optional (serviceManagement.credentialReferenceConfigured tlsCertificate) "tls-certificate"
      ++ lib.optional (serviceManagement.credentialReferenceConfigured tlsPrivateKey) "tls-private-key"
      ++ lib.optional (serviceManagement.credentialReferenceConfigured tlsCa) "tls-ca"
    );
  credentialsByName = builtins.listToAttrs (builtins.map (credential: {
      inherit (credential) name;
      value = credential;
    })
    configuredCredentials);
  mainService = {
    policy.hardening = commonHardening;
    consumerInstance = "postgresql";
    service = "main";
    lifecycle = {
      description = "PostgreSQL database server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command ["run" statePlannedPath serverConfigurationPath])];
      post_start = [];
      stop = [(command ["stop" statePlannedPath])];
      post_stop = [];
      restart = "on-failure";
      restart_token = cfg.restartToken;
      restart_delay_millis = 2000;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [
        (resultOf "initialize-lifecycle" "resource")
        (resultOf "network-readiness" "resource")
      ];
      before = [];
      requires = [(resultOf "initialize-lifecycle" "resource")];
      wants = [(resultOf "network-readiness" "resource")];
    };
    supervision = {
      startup_protocol = "notification";
      notification_access = "all-processes";
    };
    readiness = {
      mechanism = "process-signal";
      signal_scope = "all-processes";
      timeout_millis = 90000;
    };
    reload = {
      strategy = "command";
      commands = [(command ["reload" statePlannedPath serverConfigurationPath])];
      completion = "command-exit";
    };
    credentials =
      if mainCredentialNames == []
      then null
      else {
        views =
          builtins.map (name: let
            credential = credentialsByName.${name};
          in {
            inherit name;
            inherit (credential.reference) encrypted;
            reference = credentialPath name;
            optional = false;
          })
          mainCredentialNames;
      };
    configuration.views = [
      {
        name = "server";
        source = serverConfigurationPath;
        optional = false;
      }
      {
        name = "host-authentication";
        source = hbaConfigurationPath;
        optional = false;
      }
    ];
    environment = {
      variables = {};
      search_path = runtimeSearchPath;
    };
    storage = commonStorage;
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    identity = commonIdentity;
    isolation = commonIsolation;
    resources.open_files = {
      kind = "maximum";
      value = 1048576;
    };
  };
  producers = [
    storage
    runtimeStorage
    networkReadiness
    credentialRequests
    hbaConfiguration
    serverConfiguration
  ];
in {
  options.postgresql = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the PostgreSQL database server.";
    };
    restartToken = lib.mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
    clusterName = lib.mkOption {
      type = nonEmptyLine;
      default = "aos";
      description = "Cluster name included in process titles and logs.";
    };
    topology = lib.mkOption {
      type = abilityTypes.enum ["standalone" "primary" "standby"];
      default = "standalone";
      description = "The database server's replication role.";
    };
    listen = {
      addresses = lib.mkOption {
        type = addressList;
        default = ["127.0.0.1" "::1"];
        description = "TCP addresses on which PostgreSQL accepts connections.";
      };
      port = lib.mkOption {
        type = port;
        default = 5432;
        description = "TCP port on which PostgreSQL accepts connections.";
      };
    };
    bootstrap = {
      superuser = lib.mkOption {
        type = identifier;
        default = "postgres";
        description = "Database superuser created when an empty cluster is initialized.";
      };
      password = lib.mkOption {
        type = credentialReference;
        default = {};
        description = "Typed source for the initial superuser password.";
      };
    };
    authentication.rules = lib.mkOption {
      type = hbaRules;
      default = [
        {
          type = "local";
          method = "peer";
        }
        {
          address = "127.0.0.1/32";
          method = "scram-sha-256";
        }
        {
          address = "::1/128";
          method = "scram-sha-256";
        }
      ];
      description = "Ordered pg_hba.conf authentication rules.";
    };
    resources = {
      maxConnections = lib.mkOption {
        type = positiveInt;
        default = 100;
        description = "Maximum concurrent client connections.";
      };
      sharedBuffers = lib.mkOption {
        type = memorySize;
        default = "128MB";
        description = "Memory dedicated to PostgreSQL shared buffers.";
      };
      workMem = lib.mkOption {
        type = memorySize;
        default = "4MB";
        description = "Memory available to each query operation before spilling.";
      };
      maintenanceWorkMem = lib.mkOption {
        type = memorySize;
        default = "64MB";
        description = "Memory available to maintenance operations.";
      };
    };
    replication = {
      walLevel = lib.mkOption {
        type = abilityTypes.enum ["minimal" "replica" "logical"];
        default = "replica";
        description = "Write-ahead log detail retained for recovery and replication.";
      };
      maxWalSenders = lib.mkOption {
        type = nonNegativeInt;
        default = 10;
        description = "Maximum concurrent WAL sender processes.";
      };
      maxReplicationSlots = lib.mkOption {
        type = nonNegativeInt;
        default = 10;
        description = "Maximum replication slots retained by this server.";
      };
      hotStandby = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Allow read-only queries while the server is in recovery.";
      };
      primary = lib.mkOption {
        type = abilityTypes.optional endpointType;
        default = null;
        description = "Primary endpoint used by a standby.";
      };
      user = lib.mkOption {
        type = identifier;
        default = "replicator";
        description = "Database role used by a standby connection.";
      };
      applicationName = lib.mkOption {
        type = identifier;
        default = "aos-standby";
        description = "Standby application name reported to the primary.";
      };
      slot = lib.mkOption {
        type = abilityTypes.optional identifier;
        default = null;
        description = "Optional physical replication slot consumed by the standby.";
      };
      passfile = lib.mkOption {
        type = credentialReference;
        default = {};
        description = "Typed source for the libpq passfile used by a standby.";
      };
    };
    tls = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Enable TLS for TCP connections.";
      };
      certificate = lib.mkOption {
        type = credentialReference;
        default = {};
        description = "Typed source for the PEM server certificate.";
      };
      privateKey = lib.mkOption {
        type = credentialReference;
        default = {};
        description = "Typed source for the PEM server private key.";
      };
      ca = lib.mkOption {
        type = credentialReference;
        default = {};
        description = "Optional typed source for the client-certificate CA bundle.";
      };
      minimumProtocol = lib.mkOption {
        type = abilityTypes.enum ["TLSv1.2" "TLSv1.3"];
        default = "TLSv1.2";
        description = "Minimum accepted TLS protocol version.";
      };
    };
    settings = lib.mkOption {
      type = settingsType;
      default = {};
      description = "Additional non-secret PostgreSQL settings not owned by a dedicated option.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services = {
        "postgresql.initialize" = initService // {enable = cfg.enable;};
        "postgresql.main" = mainService // {enable = cfg.enable;};
      };
      assertions = [
        {
          assertion = !cfg.enable || (cfg.listen.addresses != [] && builtins.length cfg.listen.addresses == builtins.length (lib.unique cfg.listen.addresses));
          message = "postgresql.listen.addresses must be non-empty and contain no duplicates";
        }
        {
          assertion =
            !cfg.enable
            || cfg.topology == "standby"
            || serviceManagement.credentialReferenceConfigured bootstrapPassword;
          message = "postgresql.bootstrap.password requires a credential reference for an enabled primary or standalone cluster";
        }
        {
          assertion = !cfg.enable || builtins.all (rule: (rule.type == "local") == (rule.address == null)) hba;
          message = "local PostgreSQL authentication rules must omit address; host rules must set address";
        }
        {
          assertion = !cfg.enable || builtins.all (rule: rule.databases != [] && rule.users != []) hba;
          message = "PostgreSQL authentication rules require at least one database and user";
        }
        {
          assertion = !cfg.enable || cfg.topology != "standby" || primary != null;
          message = "PostgreSQL standby topology requires replication.primary";
        }
        {
          assertion =
            !cfg.enable
            || cfg.topology != "standby"
            || serviceManagement.credentialReferenceConfigured replicationPassfile;
          message = "PostgreSQL standby topology requires a replication.passfile credential reference";
        }
        {
          assertion = !cfg.enable || cfg.topology == "standalone" || (cfg.replication.walLevel != "minimal" && cfg.replication.maxWalSenders > 0);
          message = "PostgreSQL primary and standby topology require replica/logical WAL and at least one WAL sender";
        }
        {
          assertion =
            !cfg.enable
            || !cfg.tls.enable
            || (
              serviceManagement.credentialReferenceConfigured tlsCertificate
              && serviceManagement.credentialReferenceConfigured tlsPrivateKey
            );
          message = "TLS-enabled PostgreSQL requires certificate and private-key resource references";
        }
        {
          assertion =
            !cfg.enable
            || builtins.all
            (rule:
              rule.method
              != "cert"
              || (
                rule.type
                == "hostssl"
                && cfg.tls.enable
                && serviceManagement.credentialReferenceConfigured tlsCa
              ))
            hba;
          message = "PostgreSQL cert authentication requires a hostssl rule, TLS, and a CA resource reference";
        }
        {
          assertion = !cfg.enable || builtins.all (name: settingName.check name) (builtins.attrNames cfg.settings);
          message = "postgresql.settings names must use lowercase PostgreSQL parameter syntax";
        }
        {
          assertion =
            !cfg.enable
            || builtins.all (name:
              !(builtins.elem name [
                "cluster_name"
                "data_directory"
                "hba_file"
                "hot_standby"
                "listen_addresses"
                "logging_collector"
                "maintenance_work_mem"
                "max_connections"
                "max_replication_slots"
                "max_wal_senders"
                "port"
                "primary_conninfo"
                "primary_slot_name"
                "shared_buffers"
                "ssl"
                "ssl_ca_file"
                "ssl_cert_file"
                "ssl_key_file"
                "ssl_min_protocol_version"
                "unix_socket_directories"
                "wal_level"
                "work_mem"
              ])) (builtins.attrNames cfg.settings);
          message = "postgresql.settings must not override settings owned by dedicated options";
        }
      ];
    }
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
  ];
}
