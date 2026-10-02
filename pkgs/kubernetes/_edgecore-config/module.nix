##! Typed runtime configuration for the package-owned KubeEdge EdgeCore role.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.edgecore;
  serviceEnabled = config.aos.services.edgecore.enable;
  inherit (lib) mkOption;
  positiveInt = lib.types.ints.between 1 9007199254740991;
  refinedString = name: description: pattern: lib.types.strMatching pattern;
  address = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9.:-]*";
  nonWhitespace = lib.types.strMatching "[^[:space:]]+";
  port = lib.types.ints.between 1 65535;
  bool = value:
    if value
    then "true"
    else "false";
  credentialType = lib.types.nullOr (lib.types.submodule config.aos.abilities.credential.operations.deliver.input);
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
  deliveries = config.aos.abilities.credential.operations.deliver.effects;
  credentialPath = name: deliveries."edgecore-${name}".outputs.path;
  configuredCredentials = lib.filterAttrs (_: ref: ref != null) credentials;
  network = config.aos.abilities.network.operations.ready.effects.edgecore;
  configuration = config.aos.abilities.configuration.operations.file.effects.edgecore;
  modules = config.aos.abilities.kernelModules.operations.ensure.effects.edgecore;
  tunables = config.aos.abilities.kernelTunables.operations.ensure.effects.settings;
  service = {
    policy.devicePolicy = {
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
          create = false;
        })
        [
          "fuse"
          "kernel-message"
          "network-tunnel"
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
    service = "edgecore";
    lifecycle = {
      description = "KubeEdge edge node agent (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/edgecore";
            arguments = [
              "--config"
              configuration.outputs.path
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
        network.outputs.resource
      ];
      before = [];
      requires = [];
      wants = [network.outputs.resource];
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
        source = configuration.outputs.path;
        optional = false;
      }
    ];
    credentials.views =
      lib.mapAttrsToList (name: reference: {
        inherit name;
        reference = credentialPath name;
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
  };
in {
  options.aos.edgecore = {
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
          "https://[^[:space:]]+";
        description = "CloudHub HTTPS enrollment endpoint.";
      };
      server = mkOption {
        type =
          refinedString "CloudHub server" "a bounded host and port endpoint"
          "[^[:space:]]+:[0-9]+";
        description = "CloudHub WebSocket endpoint.";
      };
    };
    runtimeEndpoint = mkOption {
      type =
        refinedString "EdgeCore runtime endpoint" "a bounded Unix CRI endpoint"
        "unix:///[^[:space:]]+";
      default = "unix:///run/containerd/containerd.sock";
      description = "CRI runtime and image service endpoint.";
    };
    cgroupDriver = mkOption {
      type = lib.types.enum [
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
        "[^[:space:]]+";
      default = "registry.k8s.io/pause:3.10";
      description = "Pod sandbox image reference.";
    };
    tls = {
      caCertificate = mkOption {
        type = credentialType;
        default = null;
        description = "Opaque credential reference for the CloudHub certificate authority certificate.";
      };
      clientCertificate = mkOption {
        type = credentialType;
        default = null;
        description = "Opaque credential reference for this edge node's CloudHub client certificate.";
      };
      clientPrivateKey = mkOption {
        type = credentialType;
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
            !serviceEnabled
            || builtins.all
            (reference:
              reference
              != null
              && ((reference.name != null) != (reference.resource != null)))
            requiredRefs;
          message = "edgecore.enable requires CA, client certificate, and client private-key references";
        }
      ];
      aos.services.edgecore = lib.mkDefault service;
    }
    {
      aos.services.edgecore.activationAfter = lib.mkIf serviceEnabled [modules.outputs.loaded tunables.outputs.values];
    }
    (lib.mkIf serviceEnabled {
      aos.kernel.tunablePrerequisites = [modules.outputs.loaded];
      aos.kernel.sysctl = {
        "net.ipv4.ip_forward" = "1";
        "net.ipv6.conf.all.forwarding" = "1";
      };
      aos.abilities = {
        network.operations.ready.effects.edgecore.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        configuration.operations.file.effects.edgecore.input = {
          path = "/etc/edgecore/config.yaml";
          fragments = map (fragment:
            if fragment.kind == "literal"
            then fragment.text
            else fragment.value)
          configurationFragments;
          mode = "0444";
        };
        credential.operations.deliver.effects = builtins.listToAttrs (lib.mapAttrsToList (credentialName: input: {
            name = "edgecore-${credentialName}";
            value = {inherit input;};
          })
          configuredCredentials);
        kernelModules.operations.ensure.effects.edgecore.input = {
          modules = ["overlay" "br_netfilter"];
          required = true;
        };
      };
    })
  ];
}
