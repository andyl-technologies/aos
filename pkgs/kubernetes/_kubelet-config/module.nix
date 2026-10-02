##! Typed runtime configuration for the standalone kubelet package.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.kubelet;
  serviceEnabled = config.aos.services.kubelet.enable;
  inherit (lib) mkOption;
  positiveInt = lib.types.ints.between 1 9007199254740991;
  refinedString = name: description: pattern: lib.types.strMatching pattern;
  network = config.aos.abilities.network.operations.ready.effects.kubelet;
  modules = config.aos.abilities.kernelModules.operations.ensure.effects.kubelet;
  ingress = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;
  configuration = config.aos.abilities.configuration.operations.file.effects.kubelet;
  credential = config.aos.abilities.credential.operations.deliver.effects.kubelet;

  kubeletConfig = {
    apiVersion = "kubelet.config.k8s.io/v1beta1";
    kind = "KubeletConfiguration";
    inherit
      (cfg)
      address
      cgroupDriver
      clusterDomain
      failSwapOn
      maxPods
      registerNode
      staticPodPath
      ;
    clusterDNS = cfg.clusterDns;
    containerRuntimeEndpoint = cfg.runtimeEndpoint;
    port = 10250;
    readOnlyPort = 0;
    authentication = {
      anonymous.enabled = cfg.authentication.anonymous;
      webhook.enabled = cfg.registerNode;
    };
    authorization.mode =
      if cfg.registerNode
      then "Webhook"
      else "AlwaysAllow";
  };
  kubeconfigRef = cfg.kubeconfig;
  commandArgs =
    [
      "--config"
      configuration.outputs.path
      "--root-dir"
      "/var/lib/kubelet"
      "--hostname-override"
      cfg.nodeName
    ]
    ++ lib.optionals (kubeconfigRef != null) [
      "--kubeconfig"
      credential.outputs.path
    ];
  service = {
    policy.devicePolicy = {
      baseline_access = "standard-runtime-devices";
      rules = [
        {
          selector = {
            kind = "class";
            device_type = "character";
            class = "kernel-message";
          };
          read = true;
          write = true;
          create = false;
        }
      ];
    };
    policy.hardening = {
      allow_privilege_escalation = true;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = [
          "administer-host"
          "administer-network"
          "raw-network"
          "administer-resource-limits"
          "inspect-processes"
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
      network_families = [
        "ipv4"
        "ipv6"
        "route-control"
        "raw-packet"
        "local"
      ];
      memory_pressure_adjustment = 0;
      permit_realtime = true;
      permit_elevated_file_identity = true;
      process_visibility = "all";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      operation_profile = "privileged";
      isolated_identity_mapping = "none";
    };
    service = "kubelet";
    lifecycle = {
      description = "Standalone Kubernetes node agent (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/kubelet";
            arguments = commandArgs;
          };
          ignore_failure = false;
        }
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "always";
      restart_delay_millis = 5000;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [
        (network.outputs.resource)
        (ingress.outputs.resource)
      ];
      before = [];
      requires = [
        (ingress.outputs.resource)
      ];
      wants = [(network.outputs.resource)];
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
    directories.managed = [
      {
        path = "kubelet";
        purpose = "state";
        mode = "0755";
        retention = "persistent";
      }
      {
        path = "kubelet";
        purpose = "runtime";
        mode = "0755";
        retention = "restart";
      }
      {
        path = "pods";
        purpose = "logs";
        mode = "0755";
        retention = "persistent";
      }
    ];
    configuration.views = [
      {
        name = "configuration";
        source = configuration.outputs.path;
        optional = false;
      }
    ];
    credentials.views = lib.optional (kubeconfigRef != null) {
      name = "kubeconfig";
      reference = credential.outputs.path;
      encrypted = kubeconfigRef.encrypted;
      optional = true;
    };
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = ["pods"];
      directory_mode = "0755";
    };
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "main-process";
      temporary_directory = "shared";
      devices = [];
      host_paths = [
        {
          source = "/var/lib/kubelet";
          mode = "read-write";
        }
        {
          source = "/var/log/pods";
          mode = "read-write";
        }
        {
          source = "/run/containerd";
          mode = "read-write";
        }
        {
          source = "/sys/fs/cgroup";
          mode = "read-write";
        }
      ];
      permit_core_dumps = true;
    };
  };
in {
  options.aos.kubelet = {
    nodeName = mkOption {
      type =
        refinedString "kubelet node name" "a DNS-label-compatible Kubernetes node name"
        "[a-z0-9]([-a-z0-9.]*[a-z0-9])?";
      default = "aos-node";
      description = "Node name reported to the Kubernetes API.";
    };
    address = mkOption {
      type =
        refinedString "kubelet listener address" "an IP address or DNS name accepted by kubelet"
        "[A-Za-z0-9][A-Za-z0-9.:-]*";
      default = "0.0.0.0";
      description = "Address for the authenticated kubelet HTTPS endpoint.";
    };
    runtimeEndpoint = mkOption {
      type =
        refinedString "kubelet runtime endpoint" "a bounded Unix CRI endpoint"
        "unix:///[^[:space:]]+";
      default = "unix:///run/containerd/containerd.sock";
      description = "CRI runtime endpoint used to create pods and images.";
    };
    cgroupDriver = mkOption {
      type = lib.types.enum [
        "cgroupfs"
        "systemd"
      ];
      default = "systemd";
      description = "Cgroup manager shared with the container runtime.";
    };
    clusterDns = mkOption {
      type = lib.types.listOf (lib.types.strMatching "[0-9a-fA-F:.]+");
      default = ["10.43.0.10"];
      description = "DNS service addresses written into pod resolv.conf files.";
    };
    clusterDomain = mkOption {
      type =
        refinedString "cluster DNS domain" "a DNS-compatible Kubernetes cluster domain"
        "[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?";
      default = "cluster.local";
      description = "DNS domain appended to Kubernetes service names.";
    };
    staticPodPath = mkOption {
      type =
        refinedString "static pod path" "an absolute static pod directory without whitespace"
        "/[^[:space:]]+";
      default = "/var/lib/kubelet/manifests";
      description = "Host directory watched for static pod manifests.";
    };
    maxPods = mkOption {
      type = positiveInt;
      default = 110;
      description = "Maximum number of pods admitted on this node.";
    };
    failSwapOn = mkOption {
      type = lib.types.bool;
      default = true;
      description = "Refuse to start when swap is enabled on the host.";
    };
    registerNode = mkOption {
      type = lib.types.bool;
      default = true;
      description = "Register and maintain this node through the Kubernetes API. Disabling registration selects standalone authentication and authorization defaults for static-pod operation.";
    };
    authentication.anonymous = mkOption {
      type = lib.types.bool;
      default = false;
      description = "Permit unauthenticated requests to the kubelet HTTPS endpoint.";
    };
    kubeconfig = mkOption {
      type = lib.types.nullOr (lib.types.submodule config.aos.abilities.credential.operations.deliver.input);
      default = null;
      description = "Kubernetes API client identity delivered as an opaque service credential.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion =
            !serviceEnabled
            || !cfg.registerNode
            || (
              kubeconfigRef
              != null
              && ((kubeconfigRef.name != null) != (kubeconfigRef.resource != null))
            );
          message = "aos.services.kubelet.enable with aos.kubelet.registerNode requires an aos.kubelet.kubeconfig credential";
        }
        {
          assertion = cfg.clusterDns != [];
          message = "aos.kubelet.clusterDns must contain at least one address";
        }
      ];
      aos.services.kubelet = lib.mkMerge [
        (lib.mkDefault service)
        {activationAfter = [modules.outputs.loaded];}
      ];
    }
    (lib.mkIf serviceEnabled {
      aos.networkPolicy = {
        enable = lib.mkDefault true;
        ingress.kubelet.endpoints = [
          {
            transport = "tcp";
            port = 10250;
          }
        ];
      };
      aos.abilities = {
        network.operations.ready.effects.kubelet.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        kernelModules.operations.ensure.effects.kubelet.input = {
          modules = ["br_netfilter" "overlay"];
          required = true;
        };
        configuration.operations.file.effects.kubelet.input = {
          path = "/etc/kubelet/config.json";
          content = builtins.toJSON kubeletConfig;
          mode = "0444";
        };
        credential.operations.deliver.effects = lib.mkIf (kubeconfigRef != null) {
          kubelet.input = kubeconfigRef;
        };
      };
    })
  ];
}
