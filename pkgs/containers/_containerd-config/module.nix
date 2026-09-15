##! Typed, package-owned standalone containerd service declaration.
{
  config,
  lib,
  ...
}: let
  cfg = config.containerd;
  inherit (lib) mkOption types;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  pluginName = abilityTypes.refined {
    name = "containerd plugin name";
    description = "a non-empty containerd plugin identifier";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  };
  pluginNames = abilityTypes.list {
    element = pluginName;
    maxItems = 256;
  };
  persistentRoot = abilityTypes.refined {
    name = "containerd persistent root";
    description = "an absolute path beneath /var/lib/containerd";
    type = serviceTypes.storagePath;
    predicate = value: builtins.match "/var/lib/containerd(/[A-Za-z0-9._/-]+)?" value != null;
  };
  runtimeRoot = abilityTypes.refined {
    name = "containerd runtime root";
    description = "an absolute path beneath /run/containerd";
    type = serviceTypes.storagePath;
    predicate = value: builtins.match "/run/containerd(/[A-Za-z0-9._/-]+)?" value != null;
  };
  metricsAddress = abilityTypes.refined {
    name = "containerd metrics address";
    description = "a non-empty host and port accepted by containerd";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[^[:space:]]+:[0-9]+" value != null;
  };
  sandboxImage = abilityTypes.refined {
    name = "containerd sandbox image";
    description = "a non-empty image reference without whitespace";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[^[:space:]]+" value != null;
  };
  optionalMetrics = {
    type = abilityTypes.optional (abilityTypes.record {
      fields.address = metricsAddress;
    });
    optional = true;
  };
  optionalRegistry = {
    type = abilityTypes.optional (abilityTypes.record {
      fields.config_path = abilityTypes.deferredResult serviceTypes.hostPath;
    });
    optional = true;
  };
  serverConfigType = abilityTypes.record {
    fields = {
      version = abilityTypes.integer {
        minimum = 3;
        maximum = 3;
      };
      root = abilityTypes.deferredResult serviceTypes.storagePath;
      state = abilityTypes.deferredResult serviceTypes.storagePath;
      disabled_plugins = pluginNames;
      required_plugins = pluginNames;
      grpc = abilityTypes.record {
        fields.address = abilityTypes.deferredResult serviceTypes.storagePath;
      };
      metrics = optionalMetrics;
      plugins = abilityTypes.record {
        fields = {
          "io.containerd.cri.v1.images" = abilityTypes.record {
            fields = {
              snapshotter = abilityTypes.enum ["native" "overlayfs"];
              pinned_images = abilityTypes.record {
                fields.sandbox = sandboxImage;
              };
              registry = optionalRegistry;
            };
          };
          "io.containerd.cri.v1.runtime" = abilityTypes.record {
            fields.containerd = abilityTypes.record {
              fields = {
                default_runtime_name = abilityTypes.enum ["runc"];
                runtimes = abilityTypes.record {
                  fields.runc = abilityTypes.record {
                    fields = {
                      runtime_type = abilityTypes.enum ["io.containerd.runc.v2"];
                      options = abilityTypes.record {
                        fields.SystemdCgroup = abilityTypes.boolean;
                      };
                    };
                  };
                };
              };
            };
          };
        };
      };
    };
  };
  rootPath = resultOf "root-storage" "storage-path";
  statePath = resultOf "state-storage" "storage-path";
  socketPath = resultOf "grpc-socket-view" "storage-path";
  configPath = resultOf "server-configuration" "execution-path";
  serverConfig =
    {
      version = 3;
      root = rootPath;
      state = statePath;
      disabled_plugins = cfg.disabledPlugins;
      required_plugins = cfg.requiredPlugins;
      grpc.address = socketPath;
      plugins = {
        "io.containerd.cri.v1.images" =
          {
            snapshotter = cfg.snapshotter;
            pinned_images.sandbox = cfg.sandboxImage;
          }
          // lib.optionalAttrs (cfg.registryConfigResource != null) {
            registry.config_path = resultOf "registry-config-view" "host-path";
          };
        "io.containerd.cri.v1.runtime".containerd = {
          default_runtime_name = cfg.defaultRuntime;
          runtimes.runc = {
            runtime_type = "io.containerd.runc.v2";
            options.SystemdCgroup = cfg.systemdCgroup;
          };
        };
      };
    }
    // lib.optionalAttrs (cfg.metricsAddress != null) {
      metrics.address = cfg.metricsAddress;
    };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "containerd";
      inherit key interface parameters;
    };
  storage = serviceManagement.forProducers {
    consumerInstance = "containerd";
    interface = serviceManagement.interfaces.storageAllocation;
    producers = [
      {
        key = "state-storage";
        parameters = {
          name = "state";
          purpose = "runtime";
          mode = "0750";
          requested_path = cfg.state;
        };
      }
    ];
  };
  rootStorage = producer "root-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "root";
    purpose = "state";
    mode = "0750";
    requested_path = cfg.root;
  };
  grpcSocket = producer "grpc-socket-view" serviceManagement.interfaces.storageView {
    name = "grpc-socket";
    source = resultOf "state-storage" "retained-resource";
    access = "read-write";
    relative_path = cfg.grpcSocketName;
  };
  registryConfig = serviceManagement.forProducers {
    consumerInstance = "containerd";
    interface = serviceManagement.interfaces.hostPathView;
    producers = lib.optionals (cfg.registryConfigResource != null) [
      {
        key = "registry-config-view";
        parameters = {
          name = "registry-config";
          source = cfg.registryConfigResource;
          access = "read-only";
        };
      }
    ];
  };
  kernelModules = producer "kernel-modules" serviceManagement.interfaces.kernelModules {
    modules = ["overlay"];
    required = true;
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "stack-prepared";
    address_families = ["ipv4" "ipv6"];
  };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "containerd";
    declaration = {
      name = "server-configuration";
      source = serviceManagement.structuredSource {
        format = "toml";
        valueType = serverConfigType;
        value = serverConfig;
      };
      mode = "0444";
    };
  };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/containerd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "containerd";
    declaration = {
      service = "main";
      enabled = true;
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
          (resultOf "kernel-modules" "readiness-resource")
          (resultOf "network-readiness" "readiness-resource")
          (resultOf "root-storage" "retained-resource")
          (resultOf "state-storage" "retained-resource")
        ];
        before = [];
        requires = [
          (resultOf "kernel-modules" "readiness-resource")
          (resultOf "root-storage" "retained-resource")
          (resultOf "state-storage" "retained-resource")
        ];
        wants = [(resultOf "network-readiness" "readiness-resource")];
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
            source = resultOf "registry-config-view" "host-path";
            mode = "read-only";
          }
        ];
        permit_core_dumps = true;
      };
      linux_isolation = {
        allow_privilege_escalation = true;
        ambient_capabilities = [
          "CAP_CHOWN"
          "CAP_MKNOD"
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SETGID"
          "CAP_SETUID"
          "CAP_SYS_ADMIN"
          "CAP_SYS_CHROOT"
        ];
        capability_bounds = {
          kind = "restricted";
          capabilities = [
            "CAP_CHOWN"
            "CAP_MKNOD"
            "CAP_NET_ADMIN"
            "CAP_NET_RAW"
            "CAP_SETGID"
            "CAP_SETUID"
            "CAP_SYS_ADMIN"
            "CAP_SYS_CHROOT"
          ];
        };
        control_group_delegation = true;
        control_group_access = "host";
        device_namespace = "shared";
        kernel_clock_mutation = true;
        kernel_hostname_mutation = true;
        kernel_log_access = true;
        kernel_module_access = true;
        kernel_tunable_access = true;
        lock_personality = false;
        memory_write_execute = true;
        namespace_isolation = [];
        network_address_families = ["ipv4" "ipv6" "netlink" "packet" "unix"];
        oom_score_adjust = -999;
        permit_realtime = true;
        permit_suid_sgid = true;
        process_visibility = "all";
        security_label = "aos-pkg-containerd";
        syscall_architectures = [];
        syscall_allow = [];
        syscall_deny = [];
        syscall_profile = "privileged";
        user_namespace_ownership = "none";
      };
    };
  };
  fragments = [
    storage
    rootStorage
    grpcSocket
    registryConfig
    kernelModules
    networkReadiness
    configuration
    service
  ];
in {
  options.containerd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Run containerd as a standalone host runtime.";
    };
    restartToken = mkOption {
      type = types.nullOr serviceTypes.restartToken;
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
      type = abilityTypes.relativePath;
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
      description = "Whether runc delegates cgroup management to the selected service manager.";
    };
    sandboxImage = mkOption {
      type = sandboxImage;
      default = "registry.k8s.io/pause:3.10";
      description = "CRI pod sandbox image reference.";
    };
    registryConfigResource = mkOption {
      type = types.nullOr abilityTypes.resourceReference;
      default = null;
      description = "Optional authorized host resource containing registry configuration.";
    };
  };

  config = lib.mkMerge (
    [
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
      }
      (lib.mkIf cfg.enable {aos.abilities.instances.containerd = {};})
    ]
    ++ builtins.map
    (registry:
      lib.mkIf
      (cfg.enable && (cfg.registryConfigResource != null) == registry)
      (lib.mkMerge (builtins.map
        (fragment: {aos.abilities = fragment;})
        fragments)))
    [false true]
  );
}
