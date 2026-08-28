##! Typed standalone containerd runtime configuration.
{
  config,
  lib,
  ...
}: let
  cfg = config.containerd;
  inherit (lib) mkOption types;
  absoluteStatePath = types.strMatching "/var/lib/containerd(/[A-Za-z0-9._/-]+)?";
  absoluteRuntimePath = types.strMatching "/run/containerd(/[A-Za-z0-9._/-]+)?";
  pluginName = types.strMatching "[A-Za-z0-9][A-Za-z0-9._-]*";
in {
  options.containerd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Whether to run containerd as a standalone host runtime.";
    };
    root = mkOption {
      type = absoluteStatePath;
      default = "/var/lib/containerd";
      description = "Persistent containerd content and metadata root.";
    };
    state = mkOption {
      type = absoluteRuntimePath;
      default = "/run/containerd";
      description = "Volatile containerd state directory.";
    };
    grpcAddress = mkOption {
      type = absoluteRuntimePath;
      default = "/run/containerd/containerd.sock";
      description = "Unix socket used by local containerd clients.";
    };
    metricsAddress = mkOption {
      type = types.nullOr (types.strMatching "[^[:space:]]+:[0-9]+");
      default = null;
      description = "Optional Prometheus metrics listen address.";
    };
    disabledPlugins = mkOption {
      type = types.listOf pluginName;
      default = [];
      description = "Containerd plugins disabled at startup.";
    };
    requiredPlugins = mkOption {
      type = types.listOf pluginName;
      default = [];
      description = "Plugins whose initialization failure aborts startup.";
    };
    snapshotter = mkOption {
      type = types.enum ["overlayfs" "native"];
      default = "overlayfs";
      description = "Default CRI image snapshotter.";
    };
    defaultRuntime = mkOption {
      type = types.enum ["runc"];
      default = "runc";
      description = "Default OCI runtime registered with the CRI plugin.";
    };
    systemdCgroup = mkOption {
      type = types.bool;
      default = true;
      description = "Whether runc delegates cgroup management to systemd.";
    };
    sandboxImage = mkOption {
      type = types.strMatching "[^[:space:]]+";
      default = "registry.k8s.io/pause:3.10";
      description = "CRI pod sandbox image reference.";
    };
    registryConfigPath = mkOption {
      type = types.strMatching "/etc/containerd(/[A-Za-z0-9._/-]+)?";
      default = "/etc/containerd/certs.d";
      description = "Root containing host-specific registry configuration.";
    };
  };

  config = {
    assertions = [
      {
        assertion = !(lib.elem "io.containerd.cri.v1.runtime" cfg.disabledPlugins);
        message = "containerd.disabledPlugins cannot disable the configured CRI runtime plugin";
      }
    ];

    containerd.config = {
      runtime.CONTAINERD_ENABLED =
        if cfg.enable
        then "true"
        else "false";
      containerd = {
        version = 3;
        root = cfg.root;
        state = cfg.state;
        disabled_plugins = cfg.disabledPlugins;
        required_plugins = cfg.requiredPlugins;
        grpc.address = cfg.grpcAddress;
        metrics = lib.optionalAttrs (cfg.metricsAddress != null) {
          address = cfg.metricsAddress;
        };
        plugins = {
          "io.containerd.cri.v1.images" = {
            snapshotter = cfg.snapshotter;
            pinned_images.sandbox = cfg.sandboxImage;
            registry.config_path = cfg.registryConfigPath;
          };
          "io.containerd.cri.v1.runtime" = {
            containerd = {
              default_runtime_name = cfg.defaultRuntime;
              runtimes.runc = {
                runtime_type = "io.containerd.runc.v2";
                options.SystemdCgroup = cfg.systemdCgroup;
              };
            };
          };
        };
      };
    };
  };
}
