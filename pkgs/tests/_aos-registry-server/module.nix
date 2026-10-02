##! Native service and configuration declarations for the test registry server.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos-registry-server;
  listenAddress = lib.types.strWith {
    maxLength = 2048;
    pattern = "[A-Za-z0-9:._-]+";
  };
  port = lib.types.ints.between 1 65535;
  positiveInt = lib.types.ints.between 1 9007199254740991;
  literal = text: text;
  executionPath = value: value;
  command = artifact: entryPoint: arguments: {
    executable = {
      path = "${artifact}/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  selfCommand = entryPoint: arguments: command package entryPoint arguments;
  serviceFor = name: lifecycle: features:
    {
      service = name;
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

  registryStorage = config.aos.abilities.filesystem.operations.persistentAllocate.effects.registry-storage;
  cacheStorage = config.aos.abilities.filesystem.operations.persistentAllocate.effects.registry-cache;
  storeStorage = config.aos.abilities.filesystem.operations.persistentAllocate.effects.registry-store;
  runtimeStorage = config.aos.abilities.filesystem.operations.directory.effects.registry-runtime;
  registryPath = registryStorage.outputs.path;
  cachePath = cacheStorage.outputs.path;
  storePath = storeStorage.outputs.path;
  runtimePath = runtimeStorage.outputs.path;
  repositoryPath = registryPath;
  bootstrapSocket = config.aos.abilities.filesystem.operations.view.effects.registry-bootstrap-socket.outputs.path;
  ingress = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;
  files = config.aos.abilities.configuration.operations.file.effects;

  gitService =
    serviceFor "git" {
      description = "Git daemon serving AOS registries";
      execution_model = "foreground";
      start = [
        (selfCommand "bin/aos-registry-server-git" [
          files."registry-git-env-file".outputs.path
        ])
      ];
    } {
      dependencies.prerequisites = [
        ingress.outputs.resource
      ];
      configuration.views = [
        {
          name = "git";
          source = files."registry-git-env-file".outputs.path;
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
        (command dependencies.aos "bin/aos" [
          "serve"
          "--config"
          files."serve-configuration".outputs.path
        ])
      ];
    } {
      dependencies.prerequisites = [
        ingress.outputs.resource
      ];
      environment = {
        variables = {
          AOS_ROOT = storePath;
          HOME = storePath;
        };
        search_path = [
          "${dependencies.nix}"
          "${dependencies.zstd}"
          "${dependencies.coreutils}"
        ];
      };
      configuration.views = [
        {
          name = "cache";
          source = files."registry-cache-env-file".outputs.path;
          optional = false;
        }
        {
          name = "serve";
          source = files."serve-configuration".outputs.path;
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
in {
  options.aos-registry-server = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      extensible = true;
      description = "Enable at least one registry-server workload.";
    };
    restartToken = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Operator-controlled token whose change requests service restarts.";
    };
    git = {
      enable = lib.mkOption {
        type = lib.types.bool;
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
        type = lib.types.bool;
        default = true;
        description = "Export repositories without a git-daemon-export-ok marker.";
      };
    };
    cache = {
      enable = lib.mkOption {
        type = lib.types.bool;
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
        type = lib.types.bool;
        default = true;
        description = "Permit anonymous reads from the default cache view.";
      };
      maxConcurrentBuilds = lib.mkOption {
        type = positiveInt;
        default = 2;
        description = "Maximum concurrent builds admitted by the default view.";
      };
      bootstrapSocket = lib.mkOption {
        type = lib.types.addCheck lib.types.str (value: value != "" && lib.all (part: part != "" && part != "." && part != "..") (lib.splitString "/" value));
        default = "bootstrap.sock";
        description = "Bootstrap socket below the provider-managed runtime root.";
      };
      bootstrapSocketGroup = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9._-]+";
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
      aos.services = {
        "aos-registry-server.git" = gitService // {enable = cfg.enable && cfg.git.enable;};
        "aos-registry-server.cache" = cacheService // {enable = cfg.enable && cfg.cache.enable;};
      };
    }
    (lib.mkIf (cfg.enable && cfg.git.enable) {
      aos.networkPolicy = {
        enable = true;
        ingress.registry-git.endpoints = [
          {
            transport = "tcp";
            port = cfg.git.port;
          }
        ];
      };
      aos.abilities.filesystem.operations.persistentAllocate.effects.registry-storage = {
        lifetime = "persistent";
        input = {
          path = "/var/lib/aos-registry-server/registries";
          mode = "0755";
        };
      };
      aos.abilities.configuration.operations.file.effects.registry-git-env-file.input = {
        path = "/run/aos/fixtures/registry-git.env";
        fragments = [
          (literal "REGISTRY_GIT_ENABLED=true\nREGISTRY_GIT_LISTEN=${cfg.git.listenAddress}\nREGISTRY_GIT_PORT=${builtins.toString cfg.git.port}\nREGISTRY_GIT_BASE_PATH=")
          (executionPath repositoryPath)
          (literal "\nREGISTRY_GIT_EXPORT_ALL=${
            if cfg.git.exportAll
            then "true"
            else "false"
          }\n")
        ];
        mode = "0444";
      };
    })
    (lib.mkIf (cfg.enable && cfg.cache.enable) {
      aos.networkPolicy = {
        enable = true;
        ingress.registry-cache.endpoints = [
          {
            transport = "tcp";
            port = cfg.cache.port;
          }
        ];
      };
      aos.abilities.filesystem.operations = {
        persistentAllocate.effects = {
          registry-cache = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-registry-server/cache";
              mode = "0755";
            };
          };
          registry-store = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-registry-server/store-root";
              mode = "0755";
            };
          };
        };
        directory.effects.registry-runtime.input = {
          path = "/run/aos-registry-server";
          mode = "0755";
        };
        view.effects.registry-bootstrap-socket.input = {
          sourcePath = runtimePath;
          relativePath = cfg.cache.bootstrapSocket;
        };
      };
      aos.abilities.configuration.operations.file.effects.registry-cache-env-file.input = {
        path = "/run/aos/fixtures/registry-cache.env";
        content = "REGISTRY_CACHE_ENABLED=true\n";
        mode = "0444";
      };
      aos.abilities.configuration.operations.file.effects."serve-configuration".input = {
        path = "/run/aos/fixtures/serve-configuration";
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
        mode = "0444";
      };
    })
  ];
}
