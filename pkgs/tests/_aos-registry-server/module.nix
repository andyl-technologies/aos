##! Native service and configuration declarations for the test registry server.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos-registry-server;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  ingressInterface = lib.abilities.interfaces.networkPolicy.interfaces.ingress;
  inherit (lib.abilities) pathWithin resultOf;

  listenAddress = abilityTypes.refined {
    name = "registry listen address";
    description = "a hostname or numeric address accepted by the registry test services";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9:._-]+";
      }
    ];
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  command = package: entryPoint: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {inherit package;};
      entry_point = entryPoint;
      inherit arguments;
    };
    ignore_failure = false;
  };
  selfCommand = entryPoint: arguments:
    command "aos-registry-server" entryPoint arguments;
  ingressFor = key: servicePort:
    serviceManagement.forProducer {
      consumerInstance = "aos-registry-server";
      inherit key;
      interface = ingressInterface;
      methods = ["observe"];
      parameters = {
        endpoints = [
          {
            transport = "tcp";
            port = servicePort;
          }
        ];
        prerequisites = [];
      };
    };
  serviceFor = name: lifecycle: features:
    serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "aos-registry-server";
      declaration =
        {
          service = name;
          enabled = true;
          lifecycle =
            {
              environment_files = [];
              condition = [];
              pre_start = [];
              post_start = [];
              stop = [];
              post_stop = [];
              restart = "on-failure";
              restart_token = cfg.restartToken;
              restart_delay_millis = 5000;
              configuration_change_action = "restart";
              remain_after_exit = false;
              start_timeout_millis = 90000;
              stop_timeout_millis = 90000;
            }
            // lifecycle;
          identity = {
            supplementary_groups = [];
            ephemeral = true;
            file_creation_mask = "0022";
          };
          isolation = {
            privilege = "unprivileged";
            filesystem = "read-only-system";
            network = "host";
            process_visibility = "private";
            termination_scope = "all-processes";
            temporary_directory = "private";
            devices = [];
            host_paths = [];
            permit_core_dumps = false;
          };
        }
        // features;
    };

  registryStorage = serviceManagement.forProducer {
    consumerInstance = "aos-registry-server";
    key = "registry-storage";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "registries";
      purpose = "state";
      mode = "0755";
    };
  };
  cacheStorage = serviceManagement.forProducer {
    consumerInstance = "aos-registry-server";
    key = "cache-storage";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "cache";
      purpose = "state";
      mode = "0755";
    };
  };
  storeStorage = serviceManagement.forProducer {
    consumerInstance = "aos-registry-server";
    key = "store-storage";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "store-root";
      purpose = "state";
      mode = "0755";
    };
  };
  runtimeStorage = serviceManagement.forProducer {
    consumerInstance = "aos-registry-server";
    key = "runtime-storage";
    interface = serviceManagement.interfaces.storageAllocation;
    parameters = {
      name = "runtime";
      purpose = "runtime";
      mode = "0755";
    };
  };
  registryPath = resultOf "registry-storage" "storage-path";
  cachePath = resultOf "cache-storage" "storage-path";
  storePath = resultOf "store-storage" "storage-path";
  runtimePath = resultOf "runtime-storage" "storage-path";
  repositoryPath = registryPath;
  bootstrapSocket = pathWithin {
    base = runtimePath;
    relativePath = cfg.cache.bootstrapSocket;
  };
  gitIngress = ingressFor "git-ingress" cfg.git.port;
  cacheIngress = ingressFor "cache-ingress" cfg.cache.port;

  gitConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "aos-registry-server";
    declaration = {
      name = "git-configuration";
      source = {
        kind = "interpolated-text";
        fragments = [
          (literal "REGISTRY_GIT_ENABLED=true\nREGISTRY_GIT_LISTEN=${cfg.git.listenAddress}\nREGISTRY_GIT_PORT=${builtins.toString cfg.git.port}\nREGISTRY_GIT_BASE_PATH=")
          (executionPath repositoryPath)
          (literal "\nREGISTRY_GIT_EXPORT_ALL=${
            if cfg.git.exportAll
            then "true"
            else "false"
          }\n")
        ];
        maximum_size_bytes = 4096;
      };
      mode = "0444";
    };
  };
  cacheConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "aos-registry-server";
    declaration = {
      name = "cache-configuration";
      source = {
        kind = "interpolated-text";
        fragments = [(literal "REGISTRY_CACHE_ENABLED=true\n")];
        maximum_size_bytes = 4096;
      };
      mode = "0444";
    };
  };
  serveConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "aos-registry-server";
    declaration = {
      name = "serve-configuration";
      source = {
        kind = "interpolated-text";
        fragments = [
          (literal ''
            listen = "${cfg.cache.listenAddress}:${builtins.toString cfg.cache.port}"

            [[views]]
            name = "default"
            anonymous_read = ${
              if cfg.cache.anonymousRead
              then "true"
              else "false"
            }
            max_concurrent_builds = ${builtins.toString cfg.cache.maxConcurrentBuilds}

            [bootstrap]
            socket = "
          '')
          (executionPath bootstrapSocket)
          (literal ''
            "
            socket_group = "${cfg.cache.bootstrapSocketGroup}"
          '')
        ];
        maximum_size_bytes = 16384;
      };
      mode = "0444";
    };
  };

  gitService =
    serviceFor "git" {
      description = "Git daemon serving AOS registries";
      execution_model = "foreground";
      start = [
        (selfCommand "bin/aos-registry-server-git" [
          (resultOf "git-configuration" "planned-path")
        ])
      ];
    } {
      dependencies.prerequisites = [
        (resultOf "git-ingress" "readiness-resource")
      ];
      configuration.views = [
        {
          name = "git";
          source = resultOf "git-configuration" "planned-path";
          optional = false;
        }
      ];
      storage.mounts = [
        {
          name = "registries";
          source = registryPath;
          access = "read-write";
        }
      ];
    };
  cacheService =
    serviceFor "cache" {
      description = "AOS binary cache server";
      execution_model = "foreground";
      pre_start = [(selfCommand "bin/aos-registry-server-init-db" [storePath])];
      start = [
        (command "aos" "bin/aos" [
          "serve"
          "--config"
          (resultOf "serve-configuration" "planned-path")
        ])
      ];
    } {
      dependencies.prerequisites = [
        (resultOf "cache-ingress" "readiness-resource")
      ];
      environment = {
        variables = {
          AOS_ROOT = storePath;
          HOME = storePath;
        };
        search_path = [
          (lib.abilities.packageOutput {package = "nix";})
          (lib.abilities.packageOutput {package = "zstd";})
          (lib.abilities.packageOutput {package = "coreutils";})
        ];
      };
      configuration.views = [
        {
          name = "cache";
          source = resultOf "cache-configuration" "planned-path";
          optional = false;
        }
        {
          name = "serve";
          source = resultOf "serve-configuration" "planned-path";
          optional = false;
        }
      ];
      storage.mounts = [
        {
          name = "cache";
          source = cachePath;
          access = "read-write";
        }
        {
          name = "store";
          source = storePath;
          access = "read-write";
        }
        {
          name = "runtime";
          source = runtimePath;
          access = "read-write";
        }
      ];
    };

  allFragments = [
    registryStorage
    cacheStorage
    storeStorage
    runtimeStorage
    gitConfiguration
    cacheConfiguration
    serveConfiguration
    gitIngress
    cacheIngress
    gitService
    cacheService
  ];
  enabledFragments =
    lib.optionals cfg.git.enable [registryStorage gitConfiguration gitIngress gitService]
    ++ lib.optionals cfg.cache.enable [
      cacheStorage
      storeStorage
      runtimeStorage
      cacheConfiguration
      serveConfiguration
      cacheIngress
      cacheService
    ];
in {
  options.aos-registry-server = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable at least one registry-server workload.";
    };
    restartToken = lib.mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests service restarts.";
    };
    git = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Serve registry Git repositories.";
      };
      listenAddress = lib.mkOption {
        type = listenAddress;
        default = "0.0.0.0";
        description = "Address passed to the Git daemon.";
      };
      port = lib.mkOption {
        type = port;
        default = 9418;
        description = "Git protocol listen port.";
      };
      exportAll = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Export repositories without a git-daemon-export-ok marker.";
      };
    };
    cache = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Run the AOS binary-cache server.";
      };
      listenAddress = lib.mkOption {
        type = listenAddress;
        default = "0.0.0.0";
        description = "Binary-cache listen address.";
      };
      port = lib.mkOption {
        type = port;
        default = 15000;
        description = "Binary-cache listen port.";
      };
      anonymousRead = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Permit anonymous reads from the default cache view.";
      };
      maxConcurrentBuilds = lib.mkOption {
        type = positiveInt;
        default = 2;
        description = "Maximum concurrent builds admitted by the default view.";
      };
      bootstrapSocket = lib.mkOption {
        type = abilityTypes.relativePath;
        default = "bootstrap.sock";
        description = "Bootstrap socket below the provider-managed runtime root.";
      };
      bootstrapSocketGroup = lib.mkOption {
        type = abilityTypes.localKey;
        default = "root";
        description = "Group assigned to the bootstrap socket.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.enable || cfg.git.enable || cfg.cache.enable;
          message = "aos-registry-server.enable requires git.enable or cache.enable";
        }
      ];
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        allFragments);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.aos-registry-server = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        enabledFragments
      );
    })
  ];
}
