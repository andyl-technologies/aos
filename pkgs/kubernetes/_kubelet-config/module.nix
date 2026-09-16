##! Typed runtime configuration for the standalone kubelet package.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.kubelet;
  inherit (lib) mkOption;
  abilityTypes = lib.abilities.types;
  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  refinedString = name: description: pattern:
    abilityTypes.refined {
      inherit name description;
      type = abilityTypes.runtimeString;
      predicate = value: builtins.match pattern value != null;
    };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  networkPolicy = lib.abilities.interfaces.networkPolicy;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
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
  network = producer "network" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = [
      "ipv4"
      "ipv6"
    ];
  };
  ingressPolicy = producer "ingress-policy" networkPolicy.interfaces.ingress {
    endpoints = [
      {
        transport = "tcp";
        port = 10250;
      }
    ];
    prerequisites = [];
  };
  modules = producer "kernel-modules" serviceManagement.interfaces.kernelModules {
    modules = [
      "br_netfilter"
      "overlay"
    ];
    required = true;
  };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      name = "configuration";
      source = {
        kind = "inline-text";
        content = builtins.toJSON kubeletConfig;
      };
      mode = "0444";
    };
  };
  kubeconfigRef = cfg.kubeconfig;
  credential = serviceManagement.forCredentialReferences {
    consumerInstance = "service";
    references = lib.optional (kubeconfigRef != null) {
      key = "kubeconfig";
      name = "kubeconfig";
      reference = kubeconfigRef;
    };
  };
  commandArgs =
    [
      "--config"
      (resultOf "configuration" "planned-path")
      "--root-dir"
      "/var/lib/kubelet"
      "--hostname-override"
      cfg.nodeName
    ]
    ++ lib.optionals (kubeconfigRef != null) [
      "--kubeconfig"
      (resultOf "kubeconfig" "credential-path")
    ];
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_device_policy";
        requirementAlias = "linux-service-device-policy";
        description = "Requires the selected Linux platform to enforce the declared device access policy.";
        interface = "aos.platform.linux.service-device-policy";
        abi = 1;
        parameters = {
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
              create_node = false;
            }
          ];
        };
      })
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = {
          allow_privilege_escalation = true;
          ambient_capabilities = [];
          capability_bounds = {
            kind = "restricted";
            capabilities = [
              "CAP_SYS_ADMIN"
              "CAP_NET_ADMIN"
              "CAP_NET_RAW"
              "CAP_SYS_RESOURCE"
              "CAP_SYS_PTRACE"
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
          network_address_families = [
            "ipv4"
            "ipv6"
            "netlink"
            "packet"
            "unix"
          ];
          oom_score_adjust = 0;
          permit_realtime = true;
          permit_suid_sgid = true;
          process_visibility = "all";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "privileged";
          user_namespace_ownership = "none";
        };
      })
    ];
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      service = "kubelet";
      enabled = true;
      lifecycle = {
        description = "Standalone Kubernetes node agent (${packageName} ${packageVersion})";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/kubelet";
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
          (resultOf "network" "readiness-resource")
          (resultOf "kernel-modules" "readiness-resource")
          (resultOf "ingress-policy" "readiness-resource")
        ];
        before = [];
        requires = [
          (resultOf "kernel-modules" "readiness-resource")
          (resultOf "ingress-policy" "readiness-resource")
        ];
        wants = [(resultOf "network" "readiness-resource")];
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
          source = resultOf "configuration" "planned-path";
          optional = false;
        }
      ];
      credentials.views = lib.optional (kubeconfigRef != null) {
        name = "kubeconfig";
        reference = resultOf "kubeconfig" "credential-path";
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
  };
  serviceFragments = [
    network
    modules
    ingressPolicy
    configuration
    service
  ];
  credentialFragments = [credential];
  fragments = serviceFragments ++ credentialFragments;
  contributions = map serviceManagement.splitContribution fragments;
  serviceContributions = map serviceManagement.splitContribution serviceFragments;
  credentialContributions = map serviceManagement.splitContribution credentialFragments;
in {
  options.kubelet = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned standalone kubelet service.";
    };
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
      type = abilityTypes.enum [
        "cgroupfs"
        "systemd"
      ];
      default = "systemd";
      description = "Cgroup manager shared with the container runtime.";
    };
    clusterDns = mkOption {
      type = abilityTypes.list {
        element = refinedString "cluster DNS address" "an IPv4 or IPv6 DNS service address" "[0-9a-fA-F:.]+";
        maxItems = 16;
        unique = true;
        canonicalOrder = true;
      };
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
      type = abilityTypes.boolean;
      default = true;
      description = "Refuse to start when swap is enabled on the host.";
    };
    registerNode = mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Register and maintain this node through the Kubernetes API. Disabling registration selects standalone authentication and authorization defaults for static-pod operation.";
    };
    authentication.anonymous = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Permit unauthenticated requests to the kubelet HTTPS endpoint.";
    };
    kubeconfig = mkOption {
      type = abilityTypes.optional serviceTypes.credentialReference;
      default = null;
      description = "Kubernetes API client identity delivered as an opaque service credential.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion =
            !cfg.enable
            || !cfg.registerNode
            || (
              kubeconfigRef
              != null
              && serviceManagement.credentialReferenceConfigured kubeconfigRef
            );
          message = "kubelet.enable with kubelet.registerNode requires a kubelet.kubeconfig credential reference";
        }
        {
          assertion = cfg.clusterDns != [];
          message = "kubelet.clusterDns must contain at least one address";
        }
      ];
    }
    (lib.mkMerge (
      map (contribution: {aos.abilities = contribution.declarations;}) contributions
    ))
    (lib.mkIf cfg.enable (
      lib.mkMerge (
        [{aos.abilities.instances.service = {};}]
        ++ map (contribution: {aos.abilities = contribution.configured;}) serviceContributions
      )
    ))
    (lib.mkIf (cfg.enable && kubeconfigRef != null) (
      lib.mkMerge (
        map (contribution: {aos.abilities = contribution.configured;}) credentialContributions
      )
    ))
  ];
}
