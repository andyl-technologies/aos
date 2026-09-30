##! Typed, package-owned standalone containerd service declaration.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.containerd;
  inherit (lib) mkOption;
  types = lib.types;
  checkedString = pattern: types.addCheck types.str (value: builtins.match pattern value != null);
  pluginName = checkedString "[A-Za-z0-9][A-Za-z0-9._-]*";
  pluginNames = types.addCheck (types.listOf pluginName) (values: builtins.length values <= 256);
  checkedPath = pattern:
    types.addCheck (checkedString pattern) (value:
      !(lib.hasSuffix "/" value)
      && !(lib.hasInfix "//" value)
      && builtins.all (component: component != "." && component != "..") (lib.splitString "/" value));
  persistentRoot = checkedPath "/var/lib/containerd(/[A-Za-z0-9._/-]+)?";
  runtimeRoot = checkedPath "/run/containerd(/[A-Za-z0-9._/-]+)?";
  metricsAddress = checkedString "[^[:space:]]+:[0-9]+";
  sandboxImage = checkedString "[^[:space:]]+";
  directories = config.aos.abilities.filesystem.operations.directory.effects;
  views = config.aos.abilities.filesystem.operations.view.effects;
  configuration = config.aos.abilities.configuration.operations.file.effects.containerd;
  modules = config.aos.abilities.kernelModules.operations.ensure.effects.containerd;
  readiness = config.aos.abilities.network.operations.ready.effects.containerd;
  rootPath = directories.containerd-root.outputs.path;
  statePath = directories.containerd-state.outputs.path;
  socketPath = views.containerd-socket.outputs.path;
  configPath = configuration.outputs.path;
  quoted = builtins.toJSON;
  # Deferred path fragments are resolved before TOML materialization. The path
  # producers reject quotes and traversal, so their quoted values are exact.
  serverFragments =
    [
      "version = 3\nroot = \""
      rootPath
      "\"\nstate = \""
      statePath
      "\"\n"
      "disabled_plugins = ${quoted cfg.disabledPlugins}\nrequired_plugins = ${quoted cfg.requiredPlugins}\n"
      "[grpc]\naddress = \""
      socketPath
      "\"\n"
    ]
    ++ lib.optionals (cfg.metricsAddress != null) [
      "[metrics]\naddress = ${quoted cfg.metricsAddress}\n"
    ]
    ++ [
      "[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = ${quoted cfg.snapshotter}\n"
      "[plugins.\"io.containerd.cri.v1.images\".pinned_images]\nsandbox = ${quoted cfg.sandboxImage}\n"
    ]
    ++ lib.optionals (cfg.registryConfigResource != null) [
      "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \""
      views.containerd-registry.outputs.path
      "\"\n"
    ]
    ++ [
      "[plugins.\"io.containerd.cri.v1.runtime\".containerd]\ndefault_runtime_name = ${quoted cfg.defaultRuntime}\n"
      "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc]\nruntime_type = \"io.containerd.runc.v2\"\n"
      "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\nSystemdCgroup = ${quoted cfg.systemdCgroup}\n"
    ];
  command = arguments: {
    executable = {
      path = "${package}/bin/containerd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = {
    policy.hardening = {
      allow_privilege_escalation = true;
      ambient_privileges = [
        "change-file-ownership"
        "create-device-node"
        "administer-network"
        "raw-network"
        "change-group-identity"
        "change-user-identity"
        "administer-host"
        "change-root-directory"
      ];
      privilege_bounds = {
        kind = "restricted";
        privileges = [
          "change-file-ownership"
          "create-device-node"
          "administer-network"
          "raw-network"
          "change-group-identity"
          "change-user-identity"
          "administer-host"
          "change-root-directory"
        ];
      };
      resource_control_delegation = true;
      resource_control_access = "host";
      device_access_scope = "shared";
      host_clock_mutation = true;
      host_name_mutation = true;
      operating_system_log_access = true;
      operating_system_extension_access = true;
      operating_system_tunable_access = true;
      lock_execution_personality = false;
      writable_executable_memory = true;
      isolation_domains = [];
      network_families = ["ipv4" "ipv6" "route-control" "raw-packet" "local"];
      memory_pressure_adjustment = -999;
      permit_realtime = true;
      permit_elevated_file_identity = true;
      process_visibility = "all";
      security_label = "aos-pkg-containerd";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      operation_profile = "privileged";
      isolated_identity_mapping = "none";
    };
    activationAfter = [configuration.outputs.path modules.outputs.loaded];
    lifecycle = {
      description = "containerd standalone container runtime";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command ["--config" configPath])];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "always";
      restart_token = cfg.restartToken;
      restart_delay_millis = 5000;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [
        readiness.outputs.resource
        directories.containerd-root.outputs.resource
        directories.containerd-state.outputs.resource
      ];
      before = [];
      requires = [
        directories.containerd-root.outputs.resource
        directories.containerd-state.outputs.resource
      ];
      wants = [readiness.outputs.resource];
    };
    supervision = {
      startup_protocol = "notification";
      notification_access = "main-process";
    };
    readiness = {
      mechanism = "process-signal";
      signal_scope = "main-process";
      timeout_millis = 90000;
    };
    resources = {
      open_files = {
        kind = "maximum";
        value = 1048576;
      };
      processes.kind = "unbounded";
      tasks.kind = "unbounded";
    };
    configuration.views = [
      {
        name = "server";
        source = configPath;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "root";
        source = rootPath;
        access = "read-write";
      }
      {
        name = "state";
        source = statePath;
        access = "read-write";
      }
    ];
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "main-process";
      temporary_directory = "shared";
      devices = [];
      host_paths = lib.optionals (cfg.registryConfigResource != null) [
        {
          source = views.containerd-registry.outputs.path;
          mode = "read-only";
        }
      ];
      permit_core_dumps = true;
    };
  };
in {
  options.containerd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Run containerd as a standalone host runtime.";
    };
    restartToken = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
    root = mkOption {
      type = persistentRoot;
      default = "/var/lib/containerd";
      description = "Requested persistent containerd content and metadata root.";
    };
    state = mkOption {
      type = runtimeRoot;
      default = "/run/containerd";
      description = "Requested volatile containerd state directory.";
    };
    grpcSocketName = mkOption {
      type = checkedPath "[A-Za-z0-9][A-Za-z0-9._/-]*";
      default = "containerd.sock";
      description = "Socket path relative to the allocated volatile state directory.";
    };
    metricsAddress = mkOption {
      type = types.nullOr metricsAddress;
      default = null;
      description = "Optional Prometheus metrics listen address.";
    };
    disabledPlugins = mkOption {
      type = pluginNames;
      default = [];
      description = "Containerd plugins disabled at startup.";
    };
    requiredPlugins = mkOption {
      type = pluginNames;
      default = [];
      description = "Plugins whose initialization failure aborts startup.";
    };
    snapshotter = mkOption {
      type = types.enum ["native" "overlayfs"];
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
      description = "Whether runc delegates cgroup management to the selected service manager.";
    };
    sandboxImage = mkOption {
      type = sandboxImage;
      default = "registry.k8s.io/pause:3.10";
      description = "CRI pod sandbox image reference.";
    };
    registryConfigResource = mkOption {
      type = types.nullOr (checkedPath "/[A-Za-z0-9._/-]+");
      default = null;
      description = "Optional explicitly selected absolute host directory containing registry configuration.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !(lib.elem "io.containerd.cri.v1.runtime" cfg.disabledPlugins);
          message = "containerd.disabledPlugins cannot disable the configured CRI runtime plugin";
        }
        {
          assertion = builtins.length cfg.disabledPlugins == builtins.length (lib.unique cfg.disabledPlugins);
          message = "containerd.disabledPlugins must not contain duplicates";
        }
        {
          assertion = builtins.length cfg.requiredPlugins == builtins.length (lib.unique cfg.requiredPlugins);
          message = "containerd.requiredPlugins must not contain duplicates";
        }
      ];
      aos.services.containerd = service // {enable = cfg.enable;};
    }
    (lib.mkIf config.aos.services.containerd.enable {
      aos.abilities = {
        filesystem.operations.directory.effects = {
          containerd-root = {
            lifetime = "persistent";
            input = {
              path = cfg.root;
              mode = "0750";
            };
          };
          containerd-state.input = {
            path = cfg.state;
            mode = "0750";
          };
        };
        filesystem.operations.view.effects = {
          containerd-socket.input = {
            sourcePath = statePath;
            relativePath = cfg.grpcSocketName;
          };
          containerd-registry = lib.mkIf (cfg.registryConfigResource != null) {
            input.sourcePath = cfg.registryConfigResource;
          };
        };
        configuration.operations.file.effects.containerd.input = {
          path = "/run/aos/containerd/config.toml";
          fragments = serverFragments;
          mode = "0444";
        };
        kernelModules.operations.ensure.effects.containerd.input = {
          modules = ["overlay"];
          required = true;
        };
        network.operations.ready.effects.containerd.input = {
          scope = "stack-prepared";
          families = ["ipv4" "ipv6"];
        };
      };
    })
  ];
}
