##! Typed, role-aware configuration interface shared by the k3s packages.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}:
let
  inherit (lib) mkIf mkOption types;

  roleSpec = (import ./roles.nix).${packageName};
  package = packageName;
  role = roleSpec.role;
  cfg = config.k3s;

  nonEmptyStr = types.strMatching ".+";
  nullableNonEmptyStr = types.nullOr nonEmptyStr;
  labelNameRegex = "([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?";
  labelValueRegex = "([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?";
  taintRegex = "${labelNameRegex}(=${labelValueRegex})?:(NoSchedule|PreferNoSchedule|NoExecute)";
  resourceNameRegex = "[a-z0-9]([-a-z0-9.]*[a-z0-9])?";
  resourceApiVersionRegex = "[a-z0-9]([-a-z0-9.]*[a-z0-9])?(/[A-Za-z0-9]([-A-Za-z0-9.]*[A-Za-z0-9])?)?";
  resourceKindRegex = "[A-Z][A-Za-z0-9]*";
  resourceNameType = types.strMatching resourceNameRegex;
  canonicalJsonValue =
    value:
    let
      valueType = builtins.typeOf value;
    in
    if
      builtins.elem valueType [
        "null"
        "bool"
        "string"
        "int"
      ]
    then
      true
    else if valueType == "list" then
      builtins.all canonicalJsonValue value
    else if valueType == "set" then
      builtins.all canonicalJsonValue (builtins.attrValues value)
    else
      false;
  canonicalJsonObjectType = types.attrs // {
    description = "integer-profile JSON object";
    merge =
      location: definitions:
      let
        merged = types.attrs.merge location definitions;
      in
      if canonicalJsonValue merged then
        merged
      else
        throw "The option '${builtins.concatStringsSep "." location}' must contain only canonical integer-profile JSON values.";
  };
  secretRefType = lib.serviceTypes.namedSecretRef;
  cniIntegrationType = types.submodule (
    { ... }: {
      config._module.strict = true;
      options = {
        disableFlannel = mkOption {
          type = types.bool;
          default = false;
          description = "Disable the built-in Flannel implementation for this CNI integration.";
        };
        disableNetworkPolicy = mkOption {
          type = types.bool;
          default = false;
          description = "Disable the built-in network-policy controller for this CNI integration.";
        };
        disableKubeProxy = mkOption {
          type = types.bool;
          default = false;
          description = "Disable kube-proxy for this CNI integration.";
        };
      };
    }
  );
  csiIntegrationType = types.submodule (
    { ... }: {
      config._module.strict = true;
      options.nodeLabels = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "Node labels required to select nodes for this CSI integration.";
      };
    }
  );
  resourceType = types.submodule (
    { ... }: {
      config._module.strict = true;
      options = {
        apiVersion = mkOption {
          type = nonEmptyStr;
          description = "Kubernetes API group and version for the submitted object.";
        };
        kind = mkOption {
          type = nonEmptyStr;
          description = "Kubernetes kind for the submitted object.";
        };
        name = mkOption {
          type = resourceNameType;
          description = "Kubernetes metadata.name for the submitted object.";
        };
        namespace = mkOption {
          type = types.nullOr resourceNameType;
          default = null;
          description = "Kubernetes namespace, or null for a cluster-scoped object.";
        };
        spec = mkOption {
          type = canonicalJsonObjectType;
          description = "Typed integer-profile Kubernetes object spec serialized without parsing package-authored YAML.";
        };
        priority = mkOption {
          type = types.addCheck types.int (value: value >= 0 && value <= 999);
          default = 500;
          description = "Stable ordering priority used before the resource name.";
        };
      };
    }
  );
  resourceGrantType = types.submodule (
    { ... }: {
      config._module.strict = true;
      options = {
        contribution = mkOption {
          type = resourceNameType;
          description = "Authorized named contribution below k3s.integrations.resources.";
        };
        apiVersion = mkOption {
          type = nonEmptyStr;
          description = "Exact authorized Kubernetes API version.";
        };
        kind = mkOption {
          type = nonEmptyStr;
          description = "Exact authorized Kubernetes kind.";
        };
        name = mkOption {
          type = resourceNameType;
          description = "Exact authorized Kubernetes object name.";
        };
        namespace = mkOption {
          type = types.nullOr resourceNameType;
          default = null;
          description = "Exact authorized namespace, or null for cluster scope.";
        };
      };
    }
  );

  cniIntegrations = builtins.attrValues cfg.integrations.cni;
  csiIntegrations = builtins.attrValues cfg.integrations.csi;
  anyCni = field: builtins.any (integration: integration.${field}) cniIntegrations;
  integrationLabels = builtins.foldl' (
    labels: integration: labels // integration.nodeLabels
  ) { } csiIntegrations;
  nodeLabels = cfg.node.labels // integrationLabels;
  resourceNames = builtins.attrNames cfg.integrations.resources;
  renderedResources =
    builtins.sort
      (
        left: right:
        if left.priority == right.priority then left.name < right.name else left.priority < right.priority
      )
      (
        lib.mapAttrsToList (
          name: resource:
          let
            object = {
              inherit (resource) apiVersion kind spec;
              metadata = {
                inherit (resource) name;
              }
              // lib.optionalAttrs (resource.namespace != null) {
                inherit (resource) namespace;
              };
            };
          in
          {
            inherit name object;
            inherit (resource) priority;
            revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON object)}";
          }
        ) cfg.integrations.resources
      );
  resourceIdentities = map (
    resource:
    builtins.toJSON [
      resource.object.apiVersion
      resource.object.kind
      (resource.object.metadata.namespace or null)
      resource.object.metadata.name
    ]
  ) renderedResources;
  resourceAuthorized =
    contribution: resource:
    builtins.any (
      grant:
      grant.contribution == contribution
      && grant.apiVersion == resource.apiVersion
      && grant.kind == resource.kind
      && grant.name == resource.name
      && grant.namespace == resource.namespace
    ) cfg.integrations.resourceGrants;
  validResourceShapes = builtins.all (
    resource:
    builtins.match resourceApiVersionRegex resource.apiVersion != null
    && builtins.match resourceKindRegex resource.kind != null
  ) (builtins.attrValues cfg.integrations.resources);
  resourcesAuthorized = builtins.all (
    contribution: resourceAuthorized contribution cfg.integrations.resources.${contribution}
  ) resourceNames;
  addonPayload = {
    schema = "aos.kubernetes-resources/v1";
    inherit role;
    resources = renderedResources;
  };
  addonRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON addonPayload)}";
  validLabels = builtins.all (
    name:
    builtins.match labelNameRegex name != null
    && builtins.match labelValueRegex nodeLabels.${name} != null
  ) (builtins.attrNames nodeLabels);
  renderAssignments =
    values:
    builtins.mapAttrs (_: value: builtins.toString value) (
      lib.filterAttrs (_: value: value != null && value != [ ] && value != { }) values
    );
  commaList = values: lib.concatStringsSep "," values;
  labelList = values: commaList (lib.mapAttrsToList (name: value: "${name}=${value}") values);
  effectiveFlannelBackend =
    if builtins.any (integration: integration.disableFlannel) cniIntegrations then
      "none"
    else
      cfg.networking.flannelBackend;
  desiredEnv = renderAssignments {
    K3S_ENABLED = if cfg.enable then "true" else "false";
    K3S_URL = cfg.serverUrl;
    K3S_NODE_NAME = cfg.node.name;
    K3S_NODE_IP = cfg.node.ip;
    K3S_NODE_EXTERNAL_IP = cfg.node.externalIp;
    K3S_NODE_LABEL = if nodeLabels == { } then null else labelList nodeLabels;
    K3S_NODE_TAINT = if cfg.node.taints == [ ] then null else commaList cfg.node.taints;
    K3S_FLANNEL_BACKEND = effectiveFlannelBackend;
    K3S_FLANNEL_IFACE = cfg.networking.flannelInterface;
    K3S_CLUSTER_CIDR = cfg.networking.clusterCidr;
    K3S_SERVICE_CIDR = cfg.networking.serviceCidr;
    K3S_CLUSTER_DNS = cfg.networking.clusterDns;
    K3S_DISABLE_NETWORK_POLICY =
      if cfg.networking.disableNetworkPolicy || anyCni "disableNetworkPolicy" then "true" else null;
    K3S_DISABLE_KUBE_PROXY =
      if cfg.networking.disableKubeProxy || anyCni "disableKubeProxy" then "true" else null;
    K3S_CLUSTER_INIT = if cfg.server.clusterInit then "true" else null;
    K3S_DISABLE =
      if cfg.server.disableComponents == [ ] then null else commaList cfg.server.disableComponents;
    K3S_TLS_SAN = if cfg.server.tlsSans == [ ] then null else commaList cfg.server.tlsSans;
    K3S_KUBECONFIG_MODE = cfg.kubeconfigMode;
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  producer =
    key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
  tokenName = if cfg.token == null then null else lib.last (lib.splitString ":" cfg.token.ref);
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
  addonsConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      name = "addons";
      source = {
        kind = "inline-text";
        content = builtins.toJSON (addonPayload // { revision = addonRevision; });
      };
      mode = "0444";
    };
  };
  network = producer "network" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = [
      "ipv4"
      "ipv6"
    ];
  };
  modules = producer "kernel-modules" serviceManagement.interfaces.kernelModules {
    modules = roleSpec.kernelModules;
    required = true;
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
        environment_files = [ ];
        condition = [ ];
        pre_start = [ ];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput { };
              entry_point = "bin/k3s-role-start";
              arguments = [
                (resultOf "addons" "execution-path")
                (resultOf "token" "credential-path")
              ];
            };
            ignore_failure = false;
          }
        ];
        post_start = [ ];
        stop = [ ];
        post_stop = [ ];
        restart = "always";
        restart_delay_millis = 5000;
        remain_after_exit = false;
        start_timeout_millis = 90000;
        start_timeout_unbounded = true;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        after = [
          (resultOf "network" "readiness-resource")
          (resultOf "kernel-modules" "readiness-resource")
        ];
        before = [ ];
        requires = [ (resultOf "kernel-modules" "readiness-resource") ];
        wants = [ (resultOf "network" "readiness-resource") ];
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
        search_path = map (package: lib.abilities.packageOutput { inherit package; }) [
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
          "jq"
        ];
      };
      directories.managed = map (path: {
        inherit path;
        purpose = "state";
        mode = "0755";
        retention = "persistent";
      }) roleSpec.stateDirectories;
      configuration.views = [
        {
          name = "addons";
          source = resultOf "addons" "execution-path";
          optional = false;
        }
      ];
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
        directories = [ ];
        directory_mode = "0750";
      };
      identity = {
        supplementary_groups = [ ];
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
        devices = [ ];
        host_paths = map (entry: {
          source = entry.path;
          mode = if entry.mode == "rw" then "read-write" else "read-only";
        }) roleSpec.hostPaths;
        permit_core_dumps = true;
      };
      linux_isolation = {
        allow_privilege_escalation = true;
        ambient_capabilities = [ ];
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
        namespace_isolation = [ ];
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
        syscall_architectures = [ ];
        syscall_allow = [ ];
        syscall_deny = [ ];
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
    addonsConfiguration
    tokenSource
    tokenDelivery
    service
  ];
  contributions = map serviceManagement.splitContribution fragments;

in
{
  options.k3s = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the selected k3s role.";
    };

    role = mkOption {
      type = types.enum [
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
      type = types.nullOr secretRefType;
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
        type = types.attrsOf types.str;
        default = { };
        description = "Labels registered on the node.";
      };
      taints = mkOption {
        type = types.listOf nonEmptyStr;
        default = [ ];
        description = "Taints registered on the node in Kubernetes taint syntax.";
      };
    };

    networking = {
      flannelBackend = mkOption {
        type = types.enum [
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
        type = types.bool;
        default = false;
        description = "Disable the built-in network-policy controller.";
      };
      disableKubeProxy = mkOption {
        type = types.bool;
        default = false;
        description = "Disable kube-proxy for a replacement data plane.";
      };
    };

    server = {
      clusterInit = mkOption {
        type = types.bool;
        default = false;
        description = "Initialize a new embedded-etcd cluster.";
      };
      disableComponents = mkOption {
        type = types.listOf (
          types.enum [
            "coredns"
            "servicelb"
            "traefik"
            "local-storage"
            "metrics-server"
            "runtimes"
          ]
        );
        default = [ ];
        description = "Packaged server components not deployed by k3s.";
      };
      tlsSans = mkOption {
        type = types.listOf nonEmptyStr;
        default = [ ];
        description = "Additional subject alternative names for the API server certificate.";
      };
    };

    kubeconfigMode = mkOption {
      type = types.enum [
        "0600"
        "0640"
        "0644"
      ];
      default = "0600";
      description = "Mode of the administrator kubeconfig emitted by server roles.";
    };

    integrations = {
      cni = mkOption {
        type = types.attrsOf cniIntegrationType;
        default = { };
        contributable = true;
        description = "Named, package-contributable CNI integration requirements.";
      };
      csi = mkOption {
        type = types.attrsOf csiIntegrationType;
        default = { };
        contributable = true;
        description = "Named, package-contributable CSI integration requirements.";
      };
      resources = mkOption {
        type = types.attrsOf resourceType;
        default = { };
        contributable = true;
        description = "Named, package-contributable Kubernetes objects reconciled by server roles.";
      };
      resourceGrants = mkOption {
        type = types.listOf resourceGrantType;
        default = [ ];
        description = "Operator-authorized exact Kubernetes object identities.";
      };
    };
  };

  config = {
    k3s.role = role;

    aos.abilities = lib.mkMerge (
      (map (contribution: contribution.declarations) contributions)
      ++ [
        (mkIf cfg.enable (
          lib.mkMerge (
            [ { instances.service = { }; } ]
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
        assertion = builtins.all (name: builtins.match resourceNameRegex name != null) resourceNames;
        message = "k3s.integrations.resources names must use lowercase DNS-label syntax";
      }
      {
        assertion = validResourceShapes;
        message = "k3s Kubernetes resources must use normalized API versions and kinds";
      }
      {
        assertion = resourcesAuthorized;
        message = "k3s Kubernetes resource object lacks an exact operator grant";
      }
      {
        assertion = builtins.length resourceIdentities == builtins.length (lib.unique resourceIdentities);
        message = "k3s Kubernetes resource contributions must have unique object identities";
      }
      {
        assertion = builtins.all (taint: builtins.match taintRegex taint != null) cfg.node.taints;
        message = "k3s.node.taints entries must use key[=value]:effect syntax";
      }
    ];
  };
}
