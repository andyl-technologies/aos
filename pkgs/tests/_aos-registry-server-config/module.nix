##! Typed runtime configuration for the AOS registry and binary-cache server.
{
  config,
  lib,
  ...
}: let
  cfg = config."aos-registry-server";
  inherit (lib) mkIf mkOption types;
  statePath = types.strMatching "/var/lib/aos-registry-server(/[A-Za-z0-9._/-]+)?";
in {
  options."aos-registry-server" = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Whether at least one AOS registry-server workload may run.";
    };

    git = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to serve registry Git repositories.";
      };
      listenAddress = mkOption {
        type = types.strMatching "[^[:space:]]+";
        default = "0.0.0.0";
        description = "Address passed to git daemon.";
      };
      port = mkOption {
        type = types.port;
        default = 9418;
        description = "Git protocol listen port.";
      };
      basePath = mkOption {
        type = statePath;
        default = "/var/lib/aos-registry-server/registries";
        description = "Registry repository root beneath package-managed state.";
      };
      exportAll = mkOption {
        type = types.bool;
        default = true;
        description = "Whether git daemon exports repositories without git-daemon-export-ok.";
      };
    };

    cache = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to run the AOS binary-cache server.";
      };
      listenAddress = mkOption {
        type = types.strMatching "[^:[:space:]]+";
        default = "0.0.0.0";
        description = "Binary-cache listen address.";
      };
      port = mkOption {
        type = types.port;
        default = 15000;
        description = "Binary-cache listen port.";
      };
      anonymousRead = mkOption {
        type = types.bool;
        default = true;
        description = "Whether the default cache view permits anonymous reads.";
      };
      maxConcurrentBuilds = mkOption {
        type = lib.serviceTypes.positiveInt;
        default = 2;
        description = "Maximum concurrent builds admitted by the default view.";
      };
      bootstrapSocket = mkOption {
        type = types.strMatching "/run/aos-registry-server/[A-Za-z0-9._-]+";
        default = "/run/aos-registry-server/bootstrap.sock";
        description = "Volatile bootstrap control socket.";
      };
      bootstrapSocketGroup = mkOption {
        type = types.strMatching "[A-Za-z_][A-Za-z0-9_-]*";
        default = "root";
        description = "Group assigned to the bootstrap socket.";
      };
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || cfg.git.enable || cfg.cache.enable;
        message = "aos-registry-server.enable requires git.enable or cache.enable";
      }
    ];

    "aos-registry-server".config = {
      git = {
        REGISTRY_GIT_ENABLED =
          if cfg.enable && cfg.git.enable
          then "true"
          else "false";
        REGISTRY_GIT_LISTEN = cfg.git.listenAddress;
        REGISTRY_GIT_PORT = cfg.git.port;
        REGISTRY_GIT_BASE_PATH = cfg.git.basePath;
        REGISTRY_GIT_EXPORT_ALL =
          if cfg.git.exportAll
          then "true"
          else "false";
      };
      cache = {
        REGISTRY_CACHE_ENABLED =
          if cfg.enable && cfg.cache.enable
          then "true"
          else "false";
      };
      serve = {
        listen = "${cfg.cache.listenAddress}:${toString cfg.cache.port}";
        views = [
          {
            name = "default";
            anonymous_read = cfg.cache.anonymousRead;
            max_concurrent_builds = cfg.cache.maxConcurrentBuilds;
          }
        ];
        bootstrap = {
          socket = cfg.cache.bootstrapSocket;
          socket_group = cfg.cache.bootstrapSocketGroup;
        };
      };
    };
  };
}
