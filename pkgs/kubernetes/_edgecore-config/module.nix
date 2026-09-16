##! Typed runtime configuration for the package-owned KubeEdge EdgeCore role.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.edgecore;
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
  credentials = {
    ca-certificate = cfg.tls.caCertificate;
    client-certificate = cfg.tls.clientCertificate;
    client-private-key = cfg.tls.clientPrivateKey;
  };
  configurationFragments = [
    {
      kind = "literal";
      text = ''
        apiVersion: edgecore.config.kubeedge.io/v1alpha2
        kind: EdgeCore
        database:
          dataSource: /var/lib/aos-pkg-edgecore/edgecore.db
        modules:
          deviceTwin:
            enable: true
            dmiSockPath: /run/aos-pkg-edgecore/dmi.sock
          edgeHub:
            enable: true
            heartbeat: 15
            httpServer: ${cfg.cloudHub.httpServer}
            tlsCaFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "ca-certificate";
    }
    {
      kind = "literal";
      text = ''
        tlsCertFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "client-certificate";
    }
    {
      kind = "literal";
      text = ''
        tlsPrivateKeyFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "client-private-key";
    }
    {
      kind = "literal";
      text = ''
          websocket:
            enable: true
            handshakeTimeout: 30
            readDeadline: 15
            server: ${cfg.cloudHub.server}
            writeDeadline: 15
        edged:
          enable: true
          hostnameOverride: ${cfg.nodeName}
          maxContainerCount: -1
          maxPerPodContainerCount: 1
          podSandboxImage: ${cfg.podSandboxImage}
          registerNodeNamespace: default
          registerSchedulable: true
          rootDirectory: /var/lib/aos-pkg-edgecore/kubelet
          tailoredKubeletConfig:
            address: 127.0.0.1
            cgroupDriver: ${cfg.cgroupDriver}
            cgroupsPerQOS: true
            clusterDomain: cluster.local
            containerRuntimeEndpoint: ${cfg.runtimeEndpoint}
            imageServiceEndpoint: ${cfg.runtimeEndpoint}
            failSwapOn: false
            maxPods: ${toString cfg.maxPods}
            podLogsDir: /var/log/pods
            resolvConf: /etc/resolv.conf
            staticPodPath: /var/lib/aos-pkg-edgecore/manifests
        eventBus:
          enable: false
      '';
    }
  ];
  requiredRefs = builtins.attrValues credentials;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kernelTunables = lib.abilities.interfaces.kernelTunables.interface;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  credentialPath = name: resultOf "${name}-delivery" "credential-path";
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
  configuredCredentials = lib.filterAttrs (_: ref: ref != null) credentials;
  credentialRequests = serviceManagement.forCredentialReferences {
    consumerInstance = "service";
    references =
      lib.mapAttrsToList (name: reference: {
        key = "${name}-delivery";
        inherit name reference;
      })
      configuredCredentials;
  };
  network = producer "network" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = [
      "ipv4"
      "ipv6"
    ];
  };
  modules = producer "kernel-modules" serviceManagement.interfaces.kernelModules {
    modules = [
      "overlay"
      "br_netfilter"
    ];
    required = true;
  };
  tunables =
    producer "kernel-tunables" {
      alias = kernelTunables.alias;
      declaration = kernelTunables.declaration;
    } {
      values = {
        "net.ipv4.ip_forward" = "1";
        "net.ipv6.conf.all.forwarding" = "1";
      };
      dependencies = [];
    };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      name = "configuration";
      source = {
        kind = "interpolated-text";
        fragments = configurationFragments;
        maximum_size_bytes = lib.abilities.types.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      service = "edgecore";
      enabled = true;
      lifecycle = {
        description = "KubeEdge edge node agent (${packageName} ${packageVersion})";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/edgecore";
              arguments = [
                "--config"
                (resultOf "configuration" "planned-path")
              ];
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
          (resultOf "kernel-tunables" "readiness-resource")
        ];
        before = [];
        requires = [
          (resultOf "kernel-modules" "readiness-resource")
          (resultOf "kernel-tunables" "readiness-resource")
        ];
        wants = [(resultOf "network" "readiness-resource")];
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
          path = "aos-pkg-edgecore";
          purpose = "state";
          mode = "0700";
          retention = "persistent";
        }
        {
          path = "aos-pkg-edgecore";
          purpose = "runtime";
          mode = "0750";
          retention = "restart";
        }
        {
          path = "edgecore";
          purpose = "logs";
          mode = "0750";
          retention = "persistent";
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
      credentials.views =
        lib.mapAttrsToList (name: reference: {
          inherit name;
          reference = resultOf "${name}-delivery" "credential-path";
          inherit (reference) encrypted;
          optional = true;
        })
        configuredCredentials;
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [
          "edgecore"
          "pods"
        ];
        directory_mode = "0750";
      };
      identity = {
        supplementary_groups = [];
        ephemeral = false;
        file_creation_mask = "0077";
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
            source = "/run/containerd";
            mode = "read-write";
          }
          {
            source = "/sys/fs/cgroup";
            mode = "read-write";
          }
          {
            source = "/var/log/pods";
            mode = "read-write";
          }
          {
            source = "/lib/modules";
            mode = "read-only";
          }
          {
            source = "/etc/resolv.conf";
            mode = "read-only";
          }
        ];
        permit_core_dumps = true;
      };
      linux_isolation = {
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
      linux_device_policy = {
        baseline_access = "standard-runtime-devices";
        rules =
          map
          (class: {
            selector = {
              kind = "class";
              device_type = "character";
              inherit class;
            };
            read = true;
            write = true;
            create_node = false;
          })
          [
            "fuse"
            "kernel-message"
            "network-tunnel"
          ];
      };
    };
  };
  fragments = [
    network
    modules
    tunables
    configuration
    credentialRequests
    service
  ];
  contributions = map serviceManagement.splitContribution fragments;
in {
  options.edgecore = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned KubeEdge EdgeCore service.";
    };
    nodeName = mkOption {
      type =
        refinedString "EdgeCore node name" "a DNS-label-compatible Kubernetes node name"
        "[a-z0-9]([-a-z0-9.]*[a-z0-9])?";
      default = "edge-node";
      description = "Kubernetes node name advertised by EdgeCore.";
    };
    cloudHub = {
      httpServer = mkOption {
        type =
          refinedString "CloudHub HTTP server" "a bounded HTTPS CloudHub endpoint"
          "https://[^\n\r ]+";
        description = "CloudHub HTTPS enrollment endpoint.";
      };
      server = mkOption {
        type =
          refinedString "CloudHub server" "a bounded host and port endpoint"
          "[^\n\r ]+:[0-9]+";
        description = "CloudHub WebSocket endpoint.";
      };
    };
    runtimeEndpoint = mkOption {
      type =
        refinedString "EdgeCore runtime endpoint" "a bounded Unix CRI endpoint"
        "unix:///[^\n\r ]+";
      default = "unix:///run/containerd/containerd.sock";
      description = "CRI runtime and image service endpoint.";
    };
    cgroupDriver = mkOption {
      type = abilityTypes.enum [
        "cgroupfs"
        "systemd"
      ];
      default = "systemd";
      description = "Container runtime cgroup driver.";
    };
    maxPods = mkOption {
      type = positiveInt;
      default = 110;
      description = "Maximum pods admitted on the edge node.";
    };
    podSandboxImage = mkOption {
      type =
        refinedString "EdgeCore sandbox image" "a bounded image reference without whitespace"
        "[^\n\r ]+";
      default = "registry.k8s.io/pause:3.10";
      description = "Pod sandbox image reference.";
    };
    tls = {
      caCertificate = mkOption {
        type = abilityTypes.optional serviceTypes.credentialReference;
        default = null;
        description = "Opaque credential reference for the CloudHub certificate authority certificate.";
      };
      clientCertificate = mkOption {
        type = abilityTypes.optional serviceTypes.credentialReference;
        default = null;
        description = "Opaque credential reference for this edge node's CloudHub client certificate.";
      };
      clientPrivateKey = mkOption {
        type = abilityTypes.optional serviceTypes.credentialReference;
        default = null;
        description = "Opaque credential reference for this edge node's CloudHub client private key.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion =
            !cfg.enable
            || builtins.all
            (reference:
              reference
              != null
              && serviceManagement.credentialReferenceConfigured reference)
            requiredRefs;
          message = "edgecore.enable requires CA, client certificate, and client private-key references";
        }
      ];
    }
    (lib.mkMerge (
      map (contribution: {aos.abilities = contribution.declarations;}) contributions
    ))
    (lib.mkIf cfg.enable (
      lib.mkMerge (
        [{aos.abilities.instances.service = {};}]
        ++ map (contribution: {aos.abilities = contribution.configured;}) contributions
      )
    ))
  ];
}
