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
    predicate = value: builtins.stringLength value > 0;
  };
  nullableNonEmptyStr = abilityTypes.optional nonEmptyStr;
  labelNameRegex = "([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?";
  labelValueRegex = "([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?";
  taintRegex = "${labelNameRegex}(=${labelValueRegex})?:(NoSchedule|PreferNoSchedule|NoExecute)";
  secretReference = abilityTypes.refined {
    name = "K3s credential reference";
    description = "an opaque supported K3s credential reference";
    type = abilityTypes.runtimeString;
    predicate = value:
      builtins.match "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?" value != null;
  };
  secretRefType = abilityTypes.record {
    fields.ref = {
      type = secretReference;
      description = "Opaque reference to the cluster token.";
    };
  };
  objectContract = import ./object-interface.nix {inherit lib;};
  configurationContract = import ./configuration-interface.nix {inherit lib;};
  serverRole = role != "worker";
  labelValue = abilityTypes.refined {
    name = "Kubernetes label value";
    description = "a bounded Kubernetes label value";
    type = abilityTypes.string {
      maxLength = 253;
      syntax = null;
    };
    predicate = value: builtins.match labelValueRegex value != null;
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
  terminalContract = {
    alias,
    name,
    description,
    controller,
  }: let
    declaration = lib.abilities.declareInterface {
      inherit name description;
      inherit (controller.identity) abi;
      inherit (controller) requestType;
      inherit (controller.declaration) methods lifecycle;
      outputs = {};
      guarantees = [];
      aggregation = controller.declaration.aggregation // {controllerGroup = alias;};
    };
  in {
    inherit alias declaration;
    identity = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration declaration
    );
  };
  objectEffects = terminalContract {
    alias = "kubernetes-object-effects";
    name = "aos.k3s.kubernetes-object-effects";
    description = "Executes admitted Kubernetes object operations for one K3s controller-owned resource.";
    controller = objectContract.controller;
  };
  configurationEffects = terminalContract {
    alias = "k3s-configuration-effects";
    name = "aos.k3s.configuration-effects";
    description = "Executes admitted K3s configuration operations for one controller-owned resource.";
    controller = configurationContract.controller;
  };
  implementationRequirement = description: contract: methods: {
    alias = "effects";
    inherit description methods;
    accepted_interfaces = [contract.identity];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  objectImplementations = lib.optionalAttrs serverRole {
    ${objectContract.controller.alias} = {
      description = "Converges exact authorized Kubernetes objects through the packaged K3s API client.";
      interface = objectContract.controller.identity;
      artifact = objectArtifact;
      methods = objectContract.controller.methods;
      guarantees = [];
      requirements.effects =
        implementationRequirement
        "Invokes the K3s-owned terminal Kubernetes object handler."
        objectEffects
        objectContract.controller.methods;
      providerModule = {
        artifact = objectArtifact;
        path = "share/${packageName}/object-provider.nix";
      };
      desiredType = objectContract.controller.realizationType;
      requiredFeatures = [];
    };
    ${objectContract.contribution.alias} = {
      description = "Aggregates authorized package-owned Kubernetes objects into the K3s object set.";
      interface = objectContract.contribution.identity;
      artifact = objectArtifact;
      methods = objectContract.contribution.methods;
      guarantees = [];
      providerModule = {
        artifact = objectArtifact;
        path = "share/${packageName}/object-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
    ${objectEffects.alias} = {
      description = "Executes authorized Kubernetes object operations through the packaged K3s API client.";
      interface = objectEffects.alias;
      artifact = objectArtifact;
      methods = objectContract.controller.methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = objectArtifact;
        entryPoint = "libexec/aos-kubernetes-provider";
        arguments = objectContract.controller.requestType;
        result = objectContract.controller.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
  configurationInterfaces =
    {
      ${objectContract.controller.alias} = objectContract.controller.declaration;
      ${objectContract.contribution.alias} = objectContract.contribution.declaration;
      ${configurationContract.controller.alias} = configurationContract.controller.declaration;
      ${configurationContract.contribution.alias} = configurationContract.contribution.declaration;
      ${configurationEffects.alias} = configurationEffects.declaration;
    }
    // lib.optionalAttrs serverRole {
      ${objectEffects.alias} = objectEffects.declaration;
    };
  configurationImplementations = {
    ${configurationContract.controller.alias} = {
      description = "Materializes one exact K3s configuration assembled from authorized contributions.";
      interface = configurationContract.controller.alias;
      artifact = objectArtifact;
      methods = configurationContract.controller.methods;
      guarantees = [];
      requirements.effects =
        implementationRequirement
        "Invokes the K3s-owned terminal configuration handler."
        configurationEffects
        configurationContract.controller.methods;
      providerModule = {
        artifact = objectArtifact;
        path = "share/${packageName}/configuration-provider.nix";
      };
      desiredType = configurationContract.controller.realizationType;
      requiredFeatures = [];
    };
    ${configurationContract.contribution.alias} = {
      description = "Merges authorized package settings into the K3s runtime configuration.";
      interface = configurationContract.contribution.alias;
      artifact = objectArtifact;
      methods = configurationContract.contribution.methods;
      guarantees = [];
      providerModule = {
        artifact = objectArtifact;
        path = "share/${packageName}/configuration-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
    ${configurationEffects.alias} = {
      description = "Executes authorized K3s configuration operations through the package-owned handler.";
      interface = configurationEffects.alias;
      artifact = objectArtifact;
      methods = configurationContract.controller.methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = objectArtifact;
        entryPoint = "libexec/aos-kubernetes-provider";
        arguments = configurationContract.controller.requestType;
        result = configurationContract.controller.observationType;
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
  tokenName =
    if cfg.token == null
    then null
    else lib.last (lib.splitString ":" cfg.token.ref);
  tokenSource = serviceManagement.forProducers {
    consumerInstance = "service";
    interface = serviceManagement.interfaces.namedCredential;
    producers = lib.optional (tokenName != null) {
      key = "token-source";
      parameters = {
        name = tokenName;
        scope = "system";
      };
    };
  };
  tokenDelivery = serviceManagement.forProducers {
    consumerInstance = "service";
    interface = serviceManagement.interfaces.credentialDelivery;
    producers = lib.optional (tokenName != null) {
      key = "token";
      parameters = {
        name = "token";
        source = resultOf "token-source" "credential-resource";
        encrypted = false;
      };
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
    [(resultOf "ingress-policy" "readiness-resource")]
    ++ lib.optional roleSpec.acceptForwardedTraffic (resultOf "forwarding-policy" "readiness-resource");
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
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      service = "k3s";
      enabled = true;
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
                (resultOf "configuration-base" "execution-path")
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
            (resultOf "network" "readiness-resource")
            (resultOf "kernel-modules" "readiness-resource")
            (resultOf "kernel-tunables" "readiness-resource")
            (resultOf "configuration-base" "readiness-resource")
          ]
          ++ policyReadiness;
        before = [];
        requires =
          [
            (resultOf "kernel-modules" "readiness-resource")
            (resultOf "kernel-tunables" "readiness-resource")
            (resultOf "configuration-base" "readiness-resource")
          ]
          ++ policyReadiness;
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
          encrypted = false;
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
  objectController = serviceManagement.forProducer {
    consumerInstance = "service";
    key = "cluster-objects";
    interface = {
      alias = objectContract.controller.alias;
      declaration = objectContract.controller.declaration;
    };
    parameters.cluster.prerequisites = [
      (resultOf "lifecycle" "retained-resource")
    ];
    parameters.contributions = {};
  };
  configurationController = serviceManagement.forProducer {
    consumerInstance = "service";
    key = "configuration-base";
    interface = {
      alias = configurationContract.controller.alias;
      declaration = configurationContract.controller.declaration;
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
  fragments =
    [
      network
      modules
      tunables
      ingressPolicy
      tokenSource
      tokenDelivery
      service
      configurationController
    ]
    ++ lib.optional roleSpec.acceptForwardedTraffic forwardingPolicy
    ++ lib.optional serverRole objectController;
  contributions = map serviceManagement.splitContribution fragments;
in {
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
      type = abilityTypes.optional secretRefType;
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

  config = {
    k3s.role = role;

    aos.abilities = lib.mkMerge (
      [
        {
          interfaces = configurationInterfaces;
          implementations = objectImplementations // configurationImplementations;
        }
      ]
      ++ (map (contribution: contribution.declarations) contributions)
      ++ [
        (mkIf cfg.enable (
          lib.mkMerge (
            [
              {
                instances =
                  {service = {};}
                  // {configuration-controller = {};}
                  // lib.optionalAttrs serverRole {object-controller = {};};
              }
            ]
            ++ map (contribution: contribution.configured) contributions
          )
        ))
      ]
    );

    assertions = [
      {
        assertion = !cfg.enable || cfg.token != null;
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
  };
}
