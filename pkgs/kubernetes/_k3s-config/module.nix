##! Typed, role-aware configuration interface shared by the k3s packages.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  inherit (lib) mkIf mkOption;
  abilityTypes = lib.abilities.types;

  roleSpec = (import ./roles.nix).${packageName};
  package = packageName;
  role = roleSpec.role;
  cfg = config.k3s;

  nonEmptyStr = abilityTypes.refined {
    name = "non-empty K3s string";
    description = "a bounded non-empty K3s configuration value";
    type = abilityTypes.string {
      maxLength = 4096;
      syntax = null;
    };
    constraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
    ];
  };
  nullableNonEmptyStr = abilityTypes.optional nonEmptyStr;
  labelNameRegex = "([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?";
  labelValueRegex = "([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?";
  taintRegex = "${labelNameRegex}(=${labelValueRegex})?:(NoSchedule|PreferNoSchedule|NoExecute)";
  serverRole = role != "worker";
  labelValue = abilityTypes.refined {
    name = "Kubernetes label value";
    description = "a bounded Kubernetes label value";
    type = abilityTypes.string {
      maxLength = 253;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = labelValueRegex;
      }
    ];
  };
  labelsType = abilityTypes.map {
    keyMaxLength = 253;
    keySyntax = null;
    maxEntries = 256;
    value = labelValue;
  };
  nodeLabels = cfg.node.labels;
  validLabels = builtins.all (
    name:
      builtins.match labelNameRegex name
      != null
      && builtins.match labelValueRegex nodeLabels.${name} != null
  ) (builtins.attrNames nodeLabels);
  renderAssignments = values:
    builtins.mapAttrs (_: value: builtins.toString value) (
      lib.filterAttrs (_: value: value != null && value != [] && value != {}) values
    );
  commaList = values: lib.concatStringsSep "," values;
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
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kernelTunables = lib.abilities.interfaces.kernelTunables.interface;
  networkPolicy = lib.abilities.interfaces.networkPolicy;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  objectArtifact = lib.abilities.packageOutput {};
  providerArtifact = lib.abilities.packageOutput {output = "module";};
  handlerEntryPoint = "libexec/aos-kubernetes-provider";
  interfaceContract = alias: let
    declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
  in {
    inherit alias declaration;
    identity = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration declaration
    );
    methods = builtins.attrNames declaration.methods;
    requestType = declaration.requestType;
    observationType = declaration.methods.observe.outcome.observationEvidence;
  };
  objectControllerContract = interfaceContract "kubernetes-object-set";
  objectContributionContract = interfaceContract "kubernetes-objects";
  objectEffects = interfaceContract "kubernetes-object-effects";
  configurationControllerContract = interfaceContract "k3s-configuration";
  configurationContributionContract = interfaceContract "k3s-integration";
  configurationEffects = interfaceContract "k3s-configuration-effects";
  objectRealizationType = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.kubernetes.object-set-realization/v1"];
      kubeconfig = abilityTypes.executionPath;
    };
  };
  configurationRealizationType = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.k3s.configuration-realization/v1"];
      path = abilityTypes.executionPath;
    };
  };
  implementationRequirement = description: contract: {
    alias = "effects";
    inherit description;
    inherit (contract) methods;
    accepted_interfaces = [contract.identity];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  objectImplementations = lib.optionalAttrs serverRole {
    ${objectControllerContract.alias} = {
      description = "Converges exact authorized Kubernetes objects through the packaged K3s API client.";
      interface = objectControllerContract.identity;
      artifact = objectArtifact;
      methods = objectControllerContract.methods;
      guarantees = [];
      requirements.effects =
        implementationRequirement
        "Invokes the K3s-owned terminal Kubernetes object handler."
        objectEffects;
      providerModule = {
        artifact = providerArtifact;
        path = "object-provider.nix";
      };
      desiredType = objectRealizationType;
      requiredFeatures = [];
    };
    ${objectContributionContract.alias} = {
      description = "Aggregates authorized package-owned Kubernetes objects into the K3s object set.";
      interface = objectContributionContract.identity;
      artifact = objectArtifact;
      methods = objectContributionContract.methods;
      guarantees = [];
      providerModule = {
        artifact = providerArtifact;
        path = "object-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
    ${objectEffects.alias} = {
      description = "Executes authorized Kubernetes object operations through the packaged K3s API client.";
      interface = objectEffects.alias;
      artifact = objectArtifact;
      methods = objectControllerContract.methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = objectArtifact;
        entryPoint = handlerEntryPoint;
        arguments = objectControllerContract.requestType;
        result = objectControllerContract.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
  configurationImplementations = {
    ${configurationControllerContract.alias} = {
      description = "Materializes one exact K3s configuration assembled from authorized contributions.";
      interface = configurationControllerContract.alias;
      artifact = objectArtifact;
      methods = configurationControllerContract.methods;
      guarantees = [];
      requirements.effects =
        implementationRequirement
        "Invokes the K3s-owned terminal configuration handler."
        configurationEffects;
      providerModule = {
        artifact = providerArtifact;
        path = "configuration-provider.nix";
      };
      desiredType = configurationRealizationType;
      requiredFeatures = [];
    };
    ${configurationContributionContract.alias} = {
      description = "Merges authorized package settings into the K3s runtime configuration.";
      interface = configurationContributionContract.alias;
      artifact = objectArtifact;
      methods = configurationContributionContract.methods;
      guarantees = [];
      providerModule = {
        artifact = providerArtifact;
        path = "configuration-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
    ${configurationEffects.alias} = {
      description = "Executes authorized K3s configuration operations through the package-owned handler.";
      interface = configurationEffects.alias;
      artifact = objectArtifact;
      methods = configurationControllerContract.methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = objectArtifact;
        entryPoint = handlerEntryPoint;
        arguments = configurationControllerContract.requestType;
        result = configurationControllerContract.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
  tokenCredential = serviceManagement.forCredentialReferences {
    consumerInstance = "service";
    references = lib.optional (cfg.token != null) {
      key = "token";
      name = "token";
      reference = cfg.token;
    };
  };
  network = producer "network" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = [
      "ipv4"
      "ipv6"
    ];
  };
  ingressPolicy = producer "ingress-policy" networkPolicy.interfaces.ingress {
    endpoints = roleSpec.ingressEndpoints;
    prerequisites = [];
  };
  forwardingPolicy = producer "forwarding-policy" networkPolicy.interfaces.forwarding {
    policy = "accept";
    prerequisites = [];
  };
  policyReadiness =
    [(resultOf "ingress-policy" "resource")]
    ++ lib.optional roleSpec.acceptForwardedTraffic (resultOf "forwarding-policy" "resource");
  modules = producer "kernel-modules" serviceManagement.interfaces.kernelModules {
    modules = roleSpec.kernelModules;
    required = true;
  };
  tunables =
    producer "kernel-tunables" {
      alias = kernelTunables.alias;
      declaration = kernelTunables.declaration;
    } {
      values = roleSpec.kernelTunables;
      dependencies = [];
    };
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
    consumerInstance = "service";
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
            artifact = lib.abilities.packageOutput {};
            entry_point = "bin/k3s-role-start";
            arguments = [
              (resultOf "configuration-base" "planned-path")
              (resultOf "token" "credential-path")
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
      after =
        [
          (resultOf "network" "resource")
          (resultOf "kernel-modules" "resource")
          (resultOf "kernel-tunables" "resource")
          (resultOf "configuration-base" "resource")
        ]
        ++ policyReadiness;
      before = [];
      requires =
        [
          (resultOf "kernel-modules" "resource")
          (resultOf "kernel-tunables" "resource")
          (resultOf "configuration-base" "resource")
        ]
        ++ policyReadiness;
      wants = [(resultOf "network" "resource")];
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
      search_path = map (package: lib.abilities.packageOutput {inherit package;}) [
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
        reference = resultOf "token" "credential-path";
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
  objectController = serviceManagement.forProducer {
    consumerInstance = "service";
    key = "cluster-objects";
    interface = {
      alias = objectControllerContract.alias;
      declaration = objectControllerContract.declaration;
    };
    parameters.cluster.prerequisites = [
      (resultOf "lifecycle" "resource")
    ];
    parameters.contributions = {};
  };
  configurationController = serviceManagement.forProducer {
    consumerInstance = "service";
    key = "configuration-base";
    interface = {
      alias = configurationControllerContract.alias;
      declaration = configurationControllerContract.declaration;
    };
    parameters = {
      base = {
        flannel_backend = cfg.networking.flannelBackend;
        disable_network_policy = cfg.networking.disableNetworkPolicy;
        disable_kube_proxy = cfg.networking.disableKubeProxy;
        node_labels = nodeLabels;
        prerequisites = [];
      };
      contributions = {};
    };
  };
  producers =
    [
      network
      modules
      tunables
      ingressPolicy
      tokenCredential
      configurationController
    ]
    ++ lib.optional roleSpec.acceptForwardedTraffic forwardingPolicy
    ++ lib.optional serverRole objectController;
in {
  imports = [
    ./configuration-interface.nix
    ./object-interface.nix
  ];

  options.k3s = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the selected k3s role.";
    };

    role = mkOption {
      type = abilityTypes.enum [
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
      type = abilityTypes.optional serviceTypes.credentialReference;
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
        type = abilityTypes.list {
          element = nonEmptyStr;
          maxItems = 256;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
        description = "Taints registered on the node in Kubernetes taint syntax.";
      };
    };

    networking = {
      flannelBackend = mkOption {
        type = abilityTypes.enum [
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
        type = abilityTypes.boolean;
        default = false;
        description = "Disable the built-in network-policy controller.";
      };
      disableKubeProxy = mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Disable kube-proxy for a replacement data plane.";
      };
    };

    server = {
      clusterInit = mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Initialize a new embedded-etcd cluster.";
      };
      disableComponents = mkOption {
        type = abilityTypes.list {
          element = abilityTypes.enum [
            "coredns"
            "servicelb"
            "traefik"
            "local-storage"
            "metrics-server"
            "runtimes"
          ];
          maxItems = 6;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
        description = "Packaged server components not deployed by k3s.";
      };
      tlsSans = mkOption {
        type = abilityTypes.list {
          element = nonEmptyStr;
          maxItems = 256;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
        description = "Additional subject alternative names for the API server certificate.";
      };
    };

    kubeconfigMode = mkOption {
      type = abilityTypes.enum [
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
      aos.services."k3s.service" = service // {enable = cfg.enable;};
      aos.abilities.implementations = objectImplementations // configurationImplementations;

      assertions = [
        {
          assertion =
            !cfg.enable
            || (
              cfg.token
              != null
              && serviceManagement.credentialReferenceConfigured cfg.token
            );
          message = "k3s.token must reference a credential when k3s is enabled";
        }
        {
          assertion = !cfg.enable || role != "worker" || cfg.serverUrl != null;
          message = "k3s.serverUrl is required for the worker role";
        }
        {
          assertion = cfg.serverUrl == null || builtins.match "https://.+" cfg.serverUrl != null;
          message = "k3s.serverUrl must use HTTPS";
        }
        {
          assertion = !cfg.server.clusterInit || role != "worker";
          message = "k3s.server.clusterInit is not valid for the worker role";
        }
        {
          assertion = !cfg.server.clusterInit || cfg.serverUrl == null;
          message = "k3s.server.clusterInit cannot be combined with k3s.serverUrl";
        }
        {
          assertion = validLabels;
          message = "k3s node label names and values must use Kubernetes label syntax";
        }
        {
          assertion = builtins.all (taint: builtins.match taintRegex taint != null) cfg.node.taints;
          message = "k3s.node.taints entries must use key[=value]:effect syntax";
        }
      ];
    }
    (mkIf cfg.enable {
      aos.abilities.instances =
        {configuration-controller = {};}
        // lib.optionalAttrs serverRole {object-controller = {};};
    })
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
  ];
}
