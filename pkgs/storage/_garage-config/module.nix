##! Typed, package-owned Garage service declaration.
{
  config,
  lib,
  ...
}: let
  cfg = config.garage;
  inherit (lib) mkOption types;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = 9007199254740991;
  };
  socketAddress = abilityTypes.refined {
    name = "Garage socket address";
    description = "a non-empty Garage socket address without whitespace";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[^[:space:]]+" value != null;
  };
  nonEmpty = abilityTypes.refined {
    name = "non-empty Garage value";
    description = "a non-empty Garage configuration value";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match ".+" value != null;
  };
  dbEngineType = abilityTypes.enum ["lmdb" "sqlite"];
  secretRef = abilityTypes.record {
    fields = {
      resource = {
        type = abilityTypes.optional (abilityTypes.deferredResult abilityTypes.resourceReference);
        default = null;
        description = "Typed resource reference producing the credential without exposing secret bytes.";
      };
      encrypted = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether the referenced credential requires encrypted delivery.";
      };
    };
  };
  normalizeSecret = reference: {
    resource = reference.resource or null;
    encrypted = reference.encrypted or false;
  };
  rpcSecret = normalizeSecret cfg.rpc.secret;
  adminToken = normalizeSecret cfg.admin.token;
  metricsToken = normalizeSecret cfg.admin.metrics.token;
  runtimeString = abilityTypes.runtimeString;
  optionalRuntimeString = {
    type = abilityTypes.optional runtimeString;
    optional = true;
  };
  serverConfigType = abilityTypes.record {
    fields = {
      metadata_dir = abilityTypes.deferredResult runtimeString;
      data_dir = abilityTypes.deferredResult runtimeString;
      db_engine = dbEngineType;
      replication_factor = positiveInt;
      rpc_bind_addr = socketAddress;
      rpc_public_addr = optionalRuntimeString;
      bootstrap_peers = abilityTypes.list {
        element = nonEmpty;
        maxItems = 2000000;
      };
      s3_api = abilityTypes.record {
        fields = {
          api_bind_addr = socketAddress;
          s3_region = nonEmpty;
          root_domain = optionalRuntimeString;
        };
      };
      s3_web = {
        type = abilityTypes.optional (abilityTypes.record {
          fields = {
            bind_addr = socketAddress;
            root_domain = nonEmpty;
          };
        });
        optional = true;
      };
      admin = {
        type = abilityTypes.optional (abilityTypes.record {
          fields = {
            api_bind_addr = socketAddress;
            metrics_require_token = abilityTypes.boolean;
          };
        });
        optional = true;
      };
    };
  };
  serverConfig =
    {
      metadata_dir = resultOf "metadata-storage" "storage-path";
      data_dir = resultOf "data-storage" "storage-path";
      db_engine = cfg.dbEngine;
      replication_factor = cfg.replicationFactor;
      rpc_bind_addr = cfg.rpc.bindAddress;
      bootstrap_peers = cfg.rpc.bootstrapPeers;
      s3_api =
        {
          api_bind_addr = cfg.s3.bindAddress;
          s3_region = cfg.s3.region;
        }
        // lib.optionalAttrs (cfg.s3.rootDomain != null) {
          root_domain = cfg.s3.rootDomain;
        };
    }
    // lib.optionalAttrs (cfg.rpc.publicAddress != null) {
      rpc_public_addr = cfg.rpc.publicAddress;
    }
    // lib.optionalAttrs cfg.web.enable {
      s3_web = {
        bind_addr = cfg.web.bindAddress;
        root_domain = cfg.web.rootDomain;
      };
    }
    // lib.optionalAttrs cfg.admin.enable {
      admin = {
        api_bind_addr = cfg.admin.bindAddress;
        metrics_require_token = cfg.admin.metrics.requireToken;
      };
    };
  credentialsFor = variant:
    [
      {
        name = "rpc-secret";
        inherit (rpcSecret) resource encrypted;
        environment_variable = "GARAGE_RPC_SECRET_FILE";
      }
    ]
    ++ lib.optionals variant.admin [
      {
        name = "admin-token";
        inherit (adminToken) resource encrypted;
        environment_variable = "GARAGE_ADMIN_TOKEN_FILE";
      }
    ]
    ++ lib.optionals (variant.admin && variant.metrics) [
      {
        name = "metrics-token";
        inherit (metricsToken) resource encrypted;
        environment_variable = "GARAGE_METRICS_TOKEN_FILE";
      }
    ];
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/garage";
      inherit arguments;
    };
    ignore_failure = false;
  };
  abilityFragmentsFor = variant: let
    producer = key: interface: parameters:
      serviceManagement.forProducer {
        consumerInstance = "garage";
        inherit key interface parameters;
      };
    credentials = credentialsFor variant;
    credentialRequests = serviceManagement.forProducers {
      consumerInstance = "garage";
      interface = serviceManagement.interfaces.credentialDelivery;
      producers =
        builtins.map (credential: {
          key = "credential-${credential.name}";
          parameters = {
            inherit (credential) name encrypted;
            source = credential.resource;
          };
        })
        credentials;
    };
    persistentStorage = serviceManagement.forProducers {
      consumerInstance = "garage";
      interface = serviceManagement.interfaces.persistentStorageAllocation;
      producers = [
        {
          key = "metadata-storage";
          parameters = {
            name = "metadata";
            purpose = "state";
            mode = "0750";
          };
        }
        {
          key = "data-storage";
          parameters = {
            name = "data";
            purpose = "state";
            mode = "0750";
          };
        }
        {
          key = "home-storage";
          parameters = {
            name = "home";
            purpose = "state";
            mode = "0750";
          };
        }
      ];
    };
    runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
      name = "runtime";
      purpose = "runtime";
      mode = "0750";
    };
    group = producer "service-group" serviceManagement.interfaces.groupResolution {
      name = "garage";
      allocation = "managed";
    };
    principal = producer "service-principal" serviceManagement.interfaces.principalResolution {
      name = "garage";
      allocation = "managed";
      description = "Garage object-storage service";
      home_directory = resultOf "home-storage" "planned-path";
      login_access = "disabled";
      primary_group = resultOf "service-group" "group-name";
      supplementary_groups = [];
    };
    networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
      scope = "configured-connectivity";
      address_families = ["ipv4" "ipv6"];
    };
    configurationRequest = serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "garage";
      declaration = {
        name = "server-configuration";
        source = serviceManagement.structuredSource {
          format = "toml";
          valueType = serverConfigType;
          value = serverConfig;
        };
        mode = "0640";
      };
    };
    serviceRequest = serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "garage";
      declaration = {
        service = "main";
        enabled = true;
        lifecycle = {
          description = "Garage object-storage server";
          execution_model = "foreground";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [(command ["-c" (resultOf "server-configuration" "planned-path") "server"])];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "on-failure";
          restart_token = cfg.restartToken;
          restart_delay_millis = 5000;
          remain_after_exit = false;
          start_timeout_millis = 90000;
          stop_timeout_millis = 60000;
        };
        dependencies = {
          after = [(resultOf "network-readiness" "readiness-resource")];
          before = [];
          requires = [];
          wants = [(resultOf "network-readiness" "readiness-resource")];
        };
        readiness = {
          mechanism = "process-running";
          signal_scope = "none";
          timeout_millis = 90000;
        };
        credentials.views =
          builtins.map (credential: {
            inherit (credential) name encrypted environment_variable;
            reference = resultOf "credential-${credential.name}" "credential-path";
            optional = false;
          })
          credentials;
        configuration.views = [
          {
            name = "server";
            source = resultOf "server-configuration" "planned-path";
            optional = false;
          }
        ];
        storage.mounts = [
          {
            name = "metadata";
            source = resultOf "metadata-storage" "planned-path";
            access = "read-write";
          }
          {
            name = "data";
            source = resultOf "data-storage" "planned-path";
            access = "read-write";
          }
          {
            name = "runtime";
            source = resultOf "runtime-storage" "planned-path";
            access = "read-write";
          }
        ];
        logging = {
          standard_output = "structured";
          standard_error = "structured";
          directories = ["garage"];
          directory_mode = "0750";
        };
        identity = {
          principal = resultOf "service-principal" "principal-name";
          primary_group = resultOf "service-group" "group-name";
          supplementary_groups = [];
          ephemeral = false;
          file_creation_mask = "0027";
        };
        isolation = {
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
        resources.open_files = {
          kind = "maximum";
          value = 65536;
        };
        linux_isolation = {
          allow_privilege_escalation = false;
          ambient_capabilities = [];
          capability_bounds = {
            kind = "restricted";
            capabilities = [];
          };
          control_group_delegation = false;
          control_group_access = "read-only";
          device_namespace = "shared";
          kernel_clock_mutation = false;
          kernel_hostname_mutation = false;
          kernel_log_access = false;
          kernel_module_access = false;
          kernel_tunable_access = false;
          lock_personality = true;
          memory_write_execute = false;
          namespace_isolation = [];
          network_address_families = ["ipv4" "ipv6" "unix"];
          oom_score_adjust = 0;
          permit_realtime = false;
          permit_suid_sgid = false;
          process_visibility = "all";
          security_label = "aos-pkg-garage";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "system-service";
          user_namespace_ownership = "none";
        };
      };
    };
  in [
    persistentStorage
    runtimeStorage
    group
    principal
    networkReadiness
    configurationRequest
    credentialRequests
    serviceRequest
  ];
  staticAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).declarations)
    (abilityFragmentsFor {
      admin = true;
      metrics = true;
    });
  configuredAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).configured)
    (abilityFragmentsFor {
      admin = cfg.admin.enable;
      metrics = cfg.admin.enable && cfg.admin.metrics.requireToken;
    });
in {
  options.garage = {
    enable = lib.mkEnableOption "the Garage object-storage service";
    restartToken = mkOption {
      type = types.nullOr serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
    dbEngine = mkOption {
      type = dbEngineType;
      default = "lmdb";
      description = "Embedded metadata database engine.";
    };
    replicationFactor = mkOption {
      type = positiveInt;
      default = 1;
      description = "Number of copies Garage maintains for each object.";
    };
    rpc = {
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3901";
        description = "Socket address used for Garage cluster RPC.";
      };
      publicAddress = mkOption {
        type = types.nullOr socketAddress;
        default = null;
        description = "Externally reachable cluster RPC address advertised to peers.";
      };
      bootstrapPeers = mkOption {
        type = types.listOf nonEmpty;
        default = [];
        description = "Garage node-ID and RPC-address peers used for cluster discovery.";
      };
      secret = mkOption {
        type = secretRef;
        default = {};
        description = "Opaque resource reference for the shared 32-byte hexadecimal RPC secret.";
      };
    };
    s3 = {
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3900";
        description = "Socket address used by the S3 API.";
      };
      region = mkOption {
        type = nonEmpty;
        default = "garage";
        description = "S3 region returned to clients and used for request signing.";
      };
      rootDomain = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "Optional DNS suffix for virtual-host-style S3 requests.";
      };
    };
    web = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Garage's public bucket website endpoint.";
      };
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3902";
        description = "Socket address used by the bucket website endpoint.";
      };
      rootDomain = mkOption {
        type = nonEmpty;
        default = ".web.garage.localhost";
        description = "DNS suffix used to select website buckets.";
      };
    };
    admin = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Garage's authenticated administration and metrics API.";
      };
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3903";
        description = "Socket address used by the administration API.";
      };
      token = mkOption {
        type = secretRef;
        default = {};
        description = "Opaque resource reference for the administration bearer token.";
      };
      metrics = {
        requireToken = mkOption {
          type = types.bool;
          default = true;
          description = "Require a bearer token when scraping metrics.";
        };
        token = mkOption {
          type = secretRef;
          default = {};
          description = "Opaque resource reference for the metrics bearer token.";
        };
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.enable || rpcSecret.resource != null;
          message = "garage.rpc.secret.resource is required when Garage is enabled";
        }
        {
          assertion = !cfg.enable || !cfg.admin.enable || adminToken.resource != null;
          message = "garage.admin.token.resource is required when the administration API is enabled";
        }
        {
          assertion = !cfg.enable || !cfg.admin.enable || !cfg.admin.metrics.requireToken || metricsToken.resource != null;
          message = "garage.admin.metrics.token.resource is required when authenticated metrics are enabled";
        }
        {
          assertion = builtins.length cfg.rpc.bootstrapPeers == builtins.length (lib.unique cfg.rpc.bootstrapPeers);
          message = "garage.rpc.bootstrapPeers must not contain duplicates";
        }
      ];
    }
    (lib.mkMerge (builtins.map
      (fragment: {aos.abilities = fragment;})
      staticAbilityFragments))
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.garage = {};}]
        ++ configuredAbilityFragments
      );
    })
  ];
}
