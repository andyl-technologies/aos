##! Owns one K3s role service and its merged configuration/object effects.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  dependencies,
  ...
}: let
  inherit (lib) mkOption;
  roleSpec = (import ./roles.nix).${packageName};
  role = roleSpec.role;
  cfg = config.k3s;
  serviceEnabled = config.aos.services.k3s.enable;
  serverRole = role != "worker";
  nonEmptyStr = lib.types.addCheck lib.types.str (value: value != "" && builtins.stringLength value <= 4096);
  nullableNonEmptyStr = lib.types.nullOr nonEmptyStr;
  labelsType = lib.types.attrsOf lib.types.str;
  labelNameRegex = "([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?";
  labelValueRegex = "([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?";
  taintRegex = "${labelNameRegex}(=${labelValueRegex})?:(NoSchedule|PreferNoSchedule|NoExecute)";
  nodeLabels = cfg.node.labels;
  validLabels = builtins.all (name: builtins.match labelNameRegex name != null && builtins.match labelValueRegex nodeLabels.${name} != null) (builtins.attrNames nodeLabels);
  commaList = lib.concatStringsSep ",";
  renderAssignments = values: builtins.mapAttrs (_: value: builtins.toString value) (lib.filterAttrs (_: value: value != null && value != [] && value != {}) values);
  desiredEnv = renderAssignments {
    K3S_URL = cfg.serverUrl;
    K3S_NODE_NAME = cfg.node.name;
    K3S_NODE_IP = cfg.node.ip;
    K3S_NODE_EXTERNAL_IP = cfg.node.externalIp;
    K3S_NODE_TAINT =
      if cfg.node.taints == []
      then null
      else commaList cfg.node.taints;
    K3S_FLANNEL_IFACE = cfg.networking.flannelInterface;
    K3S_CLUSTER_CIDR = cfg.networking.clusterCidr;
    K3S_SERVICE_CIDR = cfg.networking.serviceCidr;
    K3S_CLUSTER_DNS = cfg.networking.clusterDns;
    K3S_CLUSTER_INIT =
      if cfg.server.clusterInit
      then "true"
      else null;
    K3S_DISABLE =
      if cfg.server.disableComponents == []
      then null
      else commaList cfg.server.disableComponents;
    K3S_TLS_SAN =
      if cfg.server.tlsSans == []
      then null
      else commaList cfg.server.tlsSans;
    K3S_KUBECONFIG_MODE = cfg.kubeconfigMode;
  };
  configuration = config.aos.abilities.k3sConfiguration.operations.ensure.effects.base;
  network = config.aos.abilities.network.operations.ready.effects.k3s;
  token = config.aos.abilities.credential.operations.deliver.effects.k3s;
  modules = config.aos.abilities.kernelModules.operations.ensure.effects.k3s;
  tunables = config.aos.abilities.kernelTunables.operations.ensure.effects.settings;
  lifecycle = config.aos.abilities.serviceManagement.operations.realize.effects.k3s;
  firewall = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;
  service = {
    activationAfter = [configuration.outputs.path modules.outputs.loaded tunables.outputs.values firewall.outputs.resource];
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
    service = "k3s";
    lifecycle = {
      description = "${roleSpec.description} (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/k3s-role-start";
            arguments = [
              configuration.outputs.path
              token.outputs.path
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
      start_timeout_unbounded = true;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [network.outputs.resource];
      before = [];
      requires = [];
      wants = [network.outputs.resource];
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
    environment = {
      variables = desiredEnv;
      search_path = map (name: dependencies.${name}.outputs.out) [
        "k3s"
        "containerd"
        "runc"
        "cni-plugins"
        "iptables"
        "ipset"
        "conntrack-tools"
        "socat"
        "ethtool"
        "iproute2"
        "util-linux"
        "kmod"
        "coreutils"
      ];
    };
    directories.managed =
      map
      (path: {
        inherit path;
        purpose = "state";
        mode = "0755";
        retention = "persistent";
      })
      roleSpec.stateDirectories
      ++ map
      (path: {
        inherit path;
        purpose = "configuration";
        mode = "0755";
        retention = "persistent";
      }) [
        "rancher/k3s"
        "rancher/node"
      ];
    configuration.views = [];
    credentials.views = [
      {
        name = "token";
        reference = token.outputs.path;
        encrypted =
          if cfg.token == null
          then false
          else cfg.token.encrypted;
        optional = false;
      }
    ];
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    identity = {
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0022";
    };
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "main-process";
      temporary_directory = "shared";
      devices = [];
      host_paths =
        map (entry: {
          source = entry.path;
          mode =
            if entry.mode == "rw"
            then "read-write"
            else "read-only";
        })
        roleSpec.hostPaths;
      permit_core_dumps = true;
    };
  };
in {
  options.k3s = {
    enable = mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the selected k3s role.";
    };

    role = mkOption {
      type = lib.types.enum [
        "worker"
        "control-plane"
        "combined"
      ];
      readOnly = true;
      description = "The k3s role implemented by the selected package.";
    };

    serverUrl = mkOption {
      type = nullableNonEmptyStr;
      default = null;
      description = "HTTPS URL of an existing k3s server to join.";
    };

    token = mkOption {
      type = lib.types.nullOr (lib.types.submodule config.aos.abilities.credential.operations.deliver.input);
      default = null;
      description = "Opaque reference to the cluster token delivered as an opaque service credential.";
    };

    node = {
      name = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "Kubernetes node name.";
      };
      ip = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "IP address advertised for the node.";
      };
      externalIp = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "External IP address advertised for the node.";
      };
      labels = mkOption {
        type = labelsType;
        default = {};
        description = "Labels registered on the node.";
      };
      taints = mkOption {
        type = lib.types.listOf nonEmptyStr;
        default = [];
        description = "Taints registered on the node in Kubernetes taint syntax.";
      };
    };

    networking = {
      flannelBackend = mkOption {
        type = lib.types.enum [
          "vxlan"
          "host-gw"
          "wireguard-native"
          "none"
        ];
        default = "vxlan";
        description = "Flannel backend, or `none` when an external CNI owns pod networking.";
      };
      flannelInterface = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "Host interface used for Flannel traffic.";
      };
      clusterCidr = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "CIDR from which pod addresses are allocated.";
      };
      serviceCidr = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "CIDR from which service addresses are allocated.";
      };
      clusterDns = mkOption {
        type = nullableNonEmptyStr;
        default = null;
        description = "Cluster DNS service address.";
      };
      disableNetworkPolicy = mkOption {
        type = lib.types.bool;
        default = false;
        description = "Disable the built-in network-policy controller.";
      };
      disableKubeProxy = mkOption {
        type = lib.types.bool;
        default = false;
        description = "Disable kube-proxy for a replacement data plane.";
      };
    };

    server = {
      clusterInit = mkOption {
        type = lib.types.bool;
        default = false;
        description = "Initialize a new embedded-etcd cluster.";
      };
      disableComponents = mkOption {
        type = lib.types.listOf (lib.types.enum ["coredns" "servicelb" "traefik" "local-storage" "metrics-server" "runtimes"]);
        default = [];
        description = "Packaged server components not deployed by k3s.";
      };
      tlsSans = mkOption {
        type = lib.types.listOf nonEmptyStr;
        default = [];
        description = "Additional subject alternative names for the API server certificate.";
      };
    };

    kubeconfigMode = mkOption {
      type = lib.types.enum [
        "0600"
        "0640"
        "0644"
      ];
      default = "0600";
      description = "Mode of the administrator kubeconfig emitted by server roles.";
    };
  };

  config = lib.mkMerge [
    {
      k3s.role = role;
      aos.services.k3s = lib.mkIf cfg.enable (service // {enable = true;});
      aos.abilities.k3sConfiguration.operations.ensure.handler.program =
        package
        // {
          meta = package.meta // {mainProgram = "aos-kubernetes-provider";};
        };
      aos.abilities.kubernetes.operations.ensure.handler.program = lib.mkIf serverRole (package
        // {
          meta = package.meta // {mainProgram = "aos-kubernetes-provider";};
        });
      assertions = [
        {
          assertion = !serviceEnabled || cfg.token != null;
          message = "k3s.token must reference a delivered credential when enabled";
        }
        {
          assertion = !serviceEnabled || role != "worker" || cfg.serverUrl != null;
          message = "k3s.serverUrl is required for a worker";
        }
        {
          assertion = cfg.serverUrl == null || builtins.match "https://.+" cfg.serverUrl != null;
          message = "k3s.serverUrl must use HTTPS";
        }
        {
          assertion = !cfg.server.clusterInit || (role != "worker" && cfg.serverUrl == null);
          message = "k3s.server.clusterInit requires an independent server role";
        }
        {
          assertion = validLabels;
          message = "k3s node labels must use Kubernetes label syntax";
        }
        {
          assertion = builtins.all (taint: builtins.match taintRegex taint != null) cfg.node.taints;
          message = "k3s.node.taints must use key[=value]:effect syntax";
        }
      ];
    }
    (lib.mkIf serviceEnabled {
      aos.networkPolicy = {
        enable = lib.mkDefault true;
        ingress.k3s.endpoints = roleSpec.ingressEndpoints;
        forwarding = lib.mkIf roleSpec.acceptForwardedTraffic {k3s.policy = "accept";};
      };
      aos.kernel = {
        sysctl = roleSpec.kernelTunables;
        tunablePrerequisites = [modules.outputs.loaded];
      };
      aos.abilities = {
        k3sConfiguration.operations.ensure.effects.base.input = {
          base = {
            flannel_backend = cfg.networking.flannelBackend;
            disable_network_policy = cfg.networking.disableNetworkPolicy;
            disable_kube_proxy = cfg.networking.disableKubeProxy;
            node_labels = cfg.node.labels;
          };
          integrations = config.aos.k3s.integrations;
        };
        network.operations.ready.effects.k3s.input.scope = "address-configured";
        credential.operations.deliver.effects.k3s.input = cfg.token;
        kernelModules.operations.ensure.effects.k3s.input = {
          modules = roleSpec.kernelModules;
          required = true;
        };
        kubernetes.operations.ensure.effects.cluster = lib.mkIf serverRole {
          after = [lifecycle.outputs.resource];
          input = {
            kubeconfig = "/etc/rancher/k3s/k3s.yaml";
            object_sets = lib.mapAttrs (_: value: builtins.removeAttrs value ["enable"]) (lib.filterAttrs (_: value: value.enable) config.aos.kubernetes.objectSets);
          };
        };
      };
    })
  ];
}
