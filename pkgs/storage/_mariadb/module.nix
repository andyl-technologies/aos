##! Typed, package-owned MariaDB service declarations.
{
  config,
  lib,
  ...
}: let
  cfg = config.mariadb;
  anyServiceEnabled =
    config.aos.services."mariadb.initialize".enable
    || config.aos.services."mariadb.main".enable;
  inherit (lib) mkOption;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  address = abilityTypes.refined {
    name = "MariaDB listen address";
    description = "a MariaDB address containing only host and address punctuation";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9_.:-]+";
      }
    ];
  };
  collation = abilityTypes.refined {
    name = "MariaDB collation";
    description = "a MariaDB collation name";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9_]+";
      }
    ];
  };
  sqlMode = abilityTypes.refined {
    name = "MariaDB SQL mode list";
    description = "a comma-separated list of uppercase MariaDB SQL modes";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Z0-9_,]*";
      }
    ];
  };
  characterSet = abilityTypes.enum ["utf8mb4" "utf8mb3" "latin1"];
  credentialReference = serviceTypes.credentialReference;
  tlsCertificate = cfg.tls.certificate;
  tlsPrivateKey = cfg.tls.privateKey;
  tlsCa = cfg.tls.ca;
  adminSql = cfg.bootstrap.adminSql;
  replicationSql = cfg.bootstrap.replicationSql;

  boolValue = value:
    if value
    then "ON"
    else "OFF";
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  credentialContent = name: {
    kind = "credential-content";
    resource = resultOf "credential-${name}" "resource";
    path = resultOf "credential-${name}" "credential-path";
  };
  command = entry_point: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      inherit entry_point arguments;
    };
    ignore_failure = false;
  };
  runtimeSearchPath =
    builtins.map
    (package: lib.abilities.packageOutput {inherit package;})
    ["self" "bash" "coreutils" "sed"];
  credentials = let
    tlsCredentials =
      lib.optionals cfg.tls.enable [
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
      };
    bootstrapCredentials =
      lib.optional (serviceManagement.credentialReferenceConfigured adminSql) {
        name = "admin-bootstrap-sql";
        reference = adminSql;
      }
      ++ lib.optional (serviceManagement.credentialReferenceConfigured replicationSql) {
        name = "replication-bootstrap-sql";
        reference = replicationSql;
      };
  in {
    inherit tlsCredentials bootstrapCredentials;
    all = tlsCredentials ++ bootstrapCredentials;
  };
  abilityFragments = let
    statePath = resultOf "state-storage" "planned-path";
    runtimePath = resultOf "runtime-storage" "planned-path";
    logPath = resultOf "log-storage" "planned-path";
    configPath = resultOf "server-configuration" "planned-path";
    bootstrapPath = resultOf "bootstrap-configuration" "planned-path";
    credentialRequests = serviceManagement.forCredentialReferences {
      consumerInstance = "mariadb";
      references =
        builtins.map (credential: {
          key = "credential-${credential.name}";
          inherit (credential) name reference;
        })
        credentials.all;
    };
    storage = serviceManagement.forProducers {
      consumerInstance = "mariadb";
      interface = serviceManagement.interfaces.persistentStorageAllocation;
      producers = [
        {
          key = "state-storage";
          parameters = {
            name = "state";
            purpose = "state";
            mode = "0750";
          };
        }
        {
          key = "log-storage";
          parameters = {
            name = "logs";
            purpose = "logs";
            mode = "0750";
          };
        }
      ];
    };
    runtimeStorage = serviceManagement.forProducer {
      consumerInstance = "mariadb";
      key = "runtime-storage";
      interface = serviceManagement.interfaces.storageAllocation;
      parameters = {
        name = "runtime";
        purpose = "runtime";
        mode = "0750";
      };
    };
    serviceGroup = serviceManagement.forProducer {
      consumerInstance = "mariadb";
      key = "service-group";
      interface = serviceManagement.interfaces.groupResolution;
      parameters = {
        name = "mariadb";
        allocation = "managed";
      };
    };
    servicePrincipal = serviceManagement.forProducer {
      consumerInstance = "mariadb";
      key = "service-principal";
      interface = serviceManagement.interfaces.principalResolution;
      parameters = {
        name = "mariadb";
        allocation = "managed";
        description = "MariaDB database service";
        home_directory = statePath;
        login_access = "disabled";
        primary_group = resultOf "service-group" "group-name";
        supplementary_groups = [];
      };
    };
    networkReadiness = serviceManagement.forProducer {
      consumerInstance = "mariadb";
      key = "network-readiness";
      interface = serviceManagement.interfaces.networkReadiness;
      parameters = {
        scope = "configured-connectivity";
        address_families = ["ipv4" "ipv6"];
      };
    };
    bootstrapFragments = lib.concatLists (builtins.map (credential: [
        (credentialContent credential.name)
        (literal "\n")
      ])
      credentials.bootstrapCredentials);
    bootstrapConfiguration = serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "mariadb";
      declaration = {
        name = "bootstrap-configuration";
        source = {
          kind = "interpolated-text";
          fragments = bootstrapFragments;
          maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
        };
        mode = "0600";
      };
    };
    tlsFragments =
      if cfg.tls.enable
      then
        [
          (literal "ssl-cert=")
          (executionPath (resultOf "credential-tls-certificate" "credential-path"))
          (literal "\nssl-key=")
          (executionPath (resultOf "credential-tls-private-key" "credential-path"))
          (literal "\n")
        ]
        ++ lib.optionals (serviceManagement.credentialReferenceConfigured tlsCa) [
          (literal "ssl-ca=")
          (executionPath (resultOf "credential-tls-ca" "credential-path"))
          (literal "\n")
        ]
      else [(literal "skip-ssl\n")];
    serverConfiguration = serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "mariadb";
      declaration = {
        name = "server-configuration";
        source = {
          kind = "interpolated-text";
          fragments =
            [
              (literal "# Generated by the MariaDB package module. Do not edit.\n[client]\nsocket=")
              (executionPath runtimePath)
              (literal ''
                /mariadb.sock
                port=${toString cfg.port}

                [mariadbd]
                bind-address=${cfg.bindAddress}
                port=${toString cfg.port}
                socket=
              '')
              (executionPath runtimePath)
              (literal "/mariadb.sock\npid-file=")
              (executionPath runtimePath)
              (literal "/mariadb.pid\ndatadir=")
              (executionPath statePath)
              (literal "\nlog-error=")
              (executionPath logPath)
              (literal ''
                /error.log
                character-set-server=${cfg.characterSet}
                collation-server=${cfg.collation}
                max-connections=${toString cfg.maxConnections}
                skip-name-resolve=${boolValue cfg.skipNameResolve}
                sql-mode=${cfg.sqlMode}
              '')
            ]
            ++ lib.optionals (credentials.bootstrapCredentials != []) [
              (literal "init-file=")
              (executionPath bootstrapPath)
              (literal "\n")
            ]
            ++ tlsFragments;
          maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
        };
        mode = "0640";
      };
    };
    commonStorage.mounts = [
      {
        name = "state";
        source = statePath;
        access = "read-write";
      }
      {
        name = "runtime";
        source = runtimePath;
        access = "read-write";
      }
      {
        name = "logs";
        source = logPath;
        access = "read-write";
      }
    ];
    commonIdentity = {
      principal = resultOf "service-principal" "principal-name";
      primary_group = resultOf "service-group" "group-name";
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0027";
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
      security_label = "aos-pkg-mariadb";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    initializeService = {
      policy.hardening = commonHardening;
      consumerInstance = "mariadb";
      service = "initialize";
      lifecycle = {
        description = "Initialize MariaDB state";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command "bin/mariadb-control" ["init" configPath statePath])];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "none";
        remain_after_exit = true;
        start_timeout_millis = 90000;
        stop_timeout_millis = 60000;
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
      configuration.views = [
        {
          name = "server";
          source = configPath;
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
    mainService = {
      policy.hardening = commonHardening;
      consumerInstance = "mariadb";
      service = "main";
      lifecycle = {
        description = "MariaDB database server";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command "bin/mariadb-control" ["run" configPath])];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_token = cfg.restartToken;
        restart_delay_millis = 5000;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 60000;
      };
      dependencies = {
        after = [(resultOf "initialize-lifecycle" "resource") (resultOf "network-readiness" "resource")];
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
      credentials =
        if credentials.tlsCredentials == []
        then null
        else {
          views =
            builtins.map (credential: {
              inherit (credential) name;
              inherit (credential.reference) encrypted;
              reference = resultOf "credential-${credential.name}" "credential-path";
              optional = false;
            })
            credentials.tlsCredentials;
        };
      configuration.views =
        [
          {
            name = "server";
            source = configPath;
            optional = false;
          }
        ]
        ++ lib.optional (credentials.bootstrapCredentials != []) {
          name = "bootstrap";
          source = bootstrapPath;
          optional = false;
        };
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
        value = 65536;
      };
    };
    baseProducers = [
      storage
      runtimeStorage
      serviceGroup
      servicePrincipal
      networkReadiness
      serverConfiguration
    ];
  in {
    inherit initializeService mainService baseProducers credentialRequests bootstrapConfiguration;
  };
in {
  options.mariadb = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the MariaDB database service.";
    };
    restartToken = mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
    bindAddress = mkOption {
      type = address;
      default = "127.0.0.1";
      description = "Address on which MariaDB accepts client connections.";
    };
    port = mkOption {
      type = port;
      default = 3306;
      description = "TCP port on which MariaDB accepts client connections.";
    };
    maxConnections = mkOption {
      type = positiveInt;
      default = 151;
      description = "Maximum simultaneous MariaDB client connections.";
    };
    characterSet = mkOption {
      type = characterSet;
      default = "utf8mb4";
      description = "Default server character set.";
    };
    collation = mkOption {
      type = collation;
      default = "utf8mb4_uca1400_ai_ci";
      description = "Default server collation.";
    };
    skipNameResolve = mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Disable DNS lookups while matching client grant entries.";
    };
    sqlMode = mkOption {
      type = sqlMode;
      default = "STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION";
      description = "Comma-separated server SQL modes.";
    };
    tls = {
      enable = mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Enable TLS using credential-backed certificate material.";
      };
      certificate = mkOption {
        type = credentialReference;
        default = {};
        description = "Opaque reference for the PEM server certificate.";
      };
      privateKey = mkOption {
        type = credentialReference;
        default = {};
        description = "Opaque reference for the PEM server private key.";
      };
      ca = mkOption {
        type = credentialReference;
        default = {};
        description = "Optional opaque reference for the client CA bundle.";
      };
    };
    bootstrap = {
      adminSql = mkOption {
        type = credentialReference;
        default = {};
        description = "Optional credential containing idempotent SQL for administrator provisioning.";
      };
      replicationSql = mkOption {
        type = credentialReference;
        default = {};
        description = "Optional credential containing idempotent SQL for replication provisioning.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.services = {
        "mariadb.initialize" = abilityFragments.initializeService // {enable = cfg.enable;};
        "mariadb.main" = abilityFragments.mainService // {enable = cfg.enable;};
      };
      assertions = [
        {
          assertion =
            !anyServiceEnabled
            || !cfg.tls.enable
            || (
              serviceManagement.credentialReferenceConfigured tlsCertificate
              && serviceManagement.credentialReferenceConfigured tlsPrivateKey
            );
          message = "mariadb TLS requires certificate and private-key credential references";
        }
        {
          assertion =
            !anyServiceEnabled
            || cfg.tls.enable
            || builtins.all
            (reference: !serviceManagement.credentialReferenceConfigured reference)
            [tlsCertificate tlsPrivateKey tlsCa];
          message = "mariadb TLS credentials require mariadb.tls.enable";
        }
      ];
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = abilityFragments.baseProducers;
      enabled = anyServiceEnabled;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [abilityFragments.credentialRequests];
      enabled = anyServiceEnabled && credentials.all != [];
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [abilityFragments.bootstrapConfiguration];
      enabled = anyServiceEnabled && credentials.bootstrapCredentials != [];
    })
  ];
}
