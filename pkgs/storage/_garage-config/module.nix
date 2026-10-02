##! Package-owned Garage settings, credentials, and native runtime resources.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.garage;
  serviceEnabled = config.aos.services."garage.main".enable;
  inherit (lib) mkOption;
  types = lib.types;
  operations = config.aos.abilities;
  positiveInt = types.ints.between 1 9007199254740991;
  socketAddress = types.strMatching "[^[:space:]]+";
  nonEmpty = types.strMatching ".+";
  dbEngineType = types.enum ["lmdb" "sqlite"];
  credentialReference = types.submodule operations.credential.operations.deliver.input;
  credentialConfigured = value: (value.name != null) != (value.resource != null);
  rpcSecret = cfg.rpc.secret;
  adminToken = cfg.admin.token;
  metricsToken = cfg.admin.metrics.token;
  credentials = credentialsFor {
    admin = cfg.admin.enable;
    metrics = cfg.admin.enable && cfg.admin.metrics.requireToken;
  };
  account = operations.identity.operations.principal.effects.garage.outputs.name;
  group = operations.identity.operations.group.effects.garage.outputs.name;
  directory = path: {
    inherit path;
    mode = "0750";
    owner = account;
    inherit group;
  };
  serverConfig =
    {
      metadata_dir = operations.filesystem.operations.directory.effects.garage-metadata.outputs.path;
      data_dir = operations.filesystem.operations.directory.effects.garage-data.outputs.path;
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
        reference = rpcSecret;
        environment_variable = "GARAGE_RPC_SECRET_FILE";
      }
    ]
    ++ lib.optionals variant.admin [
      {
        name = "admin-token";
        reference = adminToken;
        environment_variable = "GARAGE_ADMIN_TOKEN_FILE";
      }
    ]
    ++ lib.optionals (variant.admin && variant.metrics) [
      {
        name = "metrics-token";
        reference = metricsToken;
        environment_variable = "GARAGE_METRICS_TOKEN_FILE";
      }
    ];
  command = arguments: {
    executable = {
      path = "${package}/bin/garage";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = {
    policy.hardening = {
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
      security_label = "aos-pkg-garage";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "return-permission-denied";
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    service = "garage";
    lifecycle = {
      description = "Garage object-storage server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command ["-c" (operations.configuration.operations.file.effects.garage.outputs.path) "server"])];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 5000;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 60000;
    };
    dependencies = {
      after = [(operations.network.operations.ready.effects.garage.outputs.resource)];
      before = [];
      requires = [];
      wants = [(operations.network.operations.ready.effects.garage.outputs.resource)];
    };
    readiness = {
      mechanism = "process-running";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    credentials.views =
      builtins.map (credential: {
        inherit (credential) name environment_variable;
        inherit (credential.reference) encrypted;
        reference = operations.credential.operations.deliver.effects."garage-${credential.name}".outputs.path;
        optional = false;
      })
      credentials;
    configuration.views = [
      {
        name = "server";
        source = operations.configuration.operations.file.effects.garage.outputs.path;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "metadata";
        source = operations.filesystem.operations.directory.effects.garage-metadata.outputs.path;
        access = "read-write";
      }
      {
        name = "data";
        source = operations.filesystem.operations.directory.effects.garage-data.outputs.path;
        access = "read-write";
      }
      {
        name = "runtime";
        source = operations.filesystem.operations.directory.effects.garage-runtime.outputs.path;
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
      principal = operations.identity.operations.principal.effects.garage.outputs.name;
      primary_group = operations.identity.operations.group.effects.garage.outputs.name;
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
  };
in {
  options.aos.garage = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the Garage object-storage service.";
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
        type = types.listWith {
          elemType = nonEmpty;
          maxItems = 2000000;
        };
        default = [];
        description = "Garage node-ID and RPC-address peers used for cluster discovery.";
      };
      secret = mkOption {
        type = credentialReference;
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
        type = credentialReference;
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
          type = credentialReference;
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
          assertion = !serviceEnabled || credentialConfigured rpcSecret;
          message = "garage.rpc.secret requires a credential reference when Garage is enabled";
        }
        {
          assertion = !serviceEnabled || !cfg.admin.enable || credentialConfigured adminToken;
          message = "garage.admin.token requires a credential reference when the administration API is enabled";
        }
        {
          assertion = !serviceEnabled || !cfg.admin.enable || !cfg.admin.metrics.requireToken || credentialConfigured metricsToken;
          message = "garage.admin.metrics.token requires a credential reference when authenticated metrics are enabled";
        }
        {
          assertion = builtins.length cfg.rpc.bootstrapPeers == builtins.length (lib.unique cfg.rpc.bootstrapPeers);
          message = "garage.rpc.bootstrapPeers must not contain duplicates";
        }
      ];
    }
    {
      aos.services."garage.main" = lib.mkDefault (service // {enable = lib.mkDefault cfg.enable;});
    }
    (lib.mkIf serviceEnabled {
      aos.abilities = {
        identity.operations = {
          group.effects.garage.input.name = "garage";
          principal.effects.garage.input = {
            name = "garage";
            description = "Garage object-storage service";
            home_directory = "/var/lib/aos-pkg-garage-home";
            primary_group = group;
          };
        };
        filesystem.operations.directory.effects = {
          garage-metadata = {
            lifetime = "persistent";
            input = directory "/var/lib/aos-pkg-garage-metadata";
          };
          garage-data = {
            lifetime = "persistent";
            input = directory "/var/lib/aos-pkg-garage-data";
          };
          garage-home = {
            lifetime = "persistent";
            input = directory "/var/lib/aos-pkg-garage-home";
          };
          garage-runtime.input = directory "/run/aos-pkg-garage";
        };
        network.operations.ready.effects.garage.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        configuration.operations.file.effects.garage.input = {
          path = "/etc/aos/packages/garage/garage.toml";
          format = "toml";
          value = serverConfig;
          mode = "0640";
          owner = account;
          inherit group;
        };
        credential.operations.deliver.effects = builtins.listToAttrs (builtins.map (credential: {
            name = "garage-${credential.name}";
            value.input = credential.reference;
          })
          credentials);
      };
    })
  ];
}
