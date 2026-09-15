##! Typed runtime configuration for the package-owned KubeEdge CloudCore role.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.cloudcore;
  inherit (lib) mkOption;
  abilityTypes = lib.abilities.types;
  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  address = abilityTypes.refined {
    name = "CloudCore listener address";
    description = "an IP address or DNS name accepted by CloudCore";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[A-Za-z0-9][A-Za-z0-9.:-]*" value != null;
  };
  nonWhitespace = abilityTypes.refined {
    name = "CloudCore non-whitespace string";
    description = "a bounded CloudCore value without whitespace";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[^\n\r ]+" value != null;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  secretReference = abilityTypes.refined {
    name = "CloudCore secret reference";
    description = "an opaque supported credential reference";
    type = abilityTypes.runtimeString;
    predicate = value:
      builtins.match "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?" value != null;
  };
  bool = value:
    if value
    then "true"
    else "false";
  secretRef = description:
    abilityTypes.record {
      fields.ref = {
        type = abilityTypes.optional secretReference;
        default = null;
        inherit description;
      };
    };
  credentials = {
    kubeconfig = cfg.kubeApi.kubeconfig.ref or null;
    ca-certificate = cfg.tls.caCertificate.ref or null;
    ca-private-key = cfg.tls.caPrivateKey.ref or null;
    server-certificate = cfg.tls.serverCertificate.ref or null;
    server-private-key = cfg.tls.serverPrivateKey.ref or null;
  };
  configurationFragments = [
    {
      kind = "literal";
      text = ''
        apiVersion: cloudcore.config.kubeedge.io/v1alpha1
        kind: CloudCore
        commonConfig:
          monitorServer:
            bindAddress: ${cfg.monitorAddress}
          tunnelPort: 10350
        kubeAPIConfig:
          burst: ${toString cfg.kubeApi.burst}
          contentType: application/vnd.kubernetes.protobuf
          kubeConfig:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "kubeconfig";
    }
    {
      kind = "literal";
      text = ''
          master: ""
          qps: ${toString cfg.kubeApi.qps}
        modules:
          cloudHub:
            advertiseAddress:
        ${lib.concatMapStringsSep "\n" (value: "    - ${value}") cfg.advertiseAddresses}
            enable: true
            https:
              address: ${cfg.https.address}
              enable: ${bool cfg.https.enable}
              port: ${toString cfg.https.port}
            nodeLimit: ${toString cfg.nodeLimit}
            tlsCAFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "ca-certificate";
    }
    {
      kind = "literal";
      text = ''
        tlsCAKeyFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "ca-private-key";
    }
    {
      kind = "literal";
      text = ''
        tlsCertFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "server-certificate";
    }
    {
      kind = "literal";
      text = ''
        tlsPrivateKeyFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "server-private-key";
    }
    {
      kind = "literal";
      text = ''
          unixsocket:
            address: unix:///var/lib/aos-pkg-cloudcore/kubeedge.sock
            enable: true
          websocket:
            address: ${cfg.websocket.address}
            enable: ${bool cfg.websocket.enable}
            port: ${toString cfg.websocket.port}
        iptablesManager:
          enable: false
          mode: internal
        router:
          enable: false
      '';
    }
  ];
  requiredRefs = builtins.attrValues credentials;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
  credentialPath = name: resultOf "${name}-delivery" "credential-path";
  configuredCredentials = lib.filterAttrs (_: ref: ref != null) credentials;
  credentialSources = serviceManagement.forProducers {
    consumerInstance = "service";
    interface = serviceManagement.interfaces.namedCredential;
    producers =
      lib.mapAttrsToList (name: ref: {
        key = "${name}-source";
        parameters = {
          name = lib.last (lib.splitString ":" ref);
          scope = "system";
        };
      })
      configuredCredentials;
  };
  credentialDeliveries = serviceManagement.forProducers {
    consumerInstance = "service";
    interface = serviceManagement.interfaces.credentialDelivery;
    producers =
      lib.mapAttrsToList (name: _: {
        key = "${name}-delivery";
        parameters = {
          inherit name;
          source = resultOf "${name}-source" "credential-resource";
          encrypted = false;
        };
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
      service = "cloudcore";
      enabled = true;
      lifecycle = {
        description = "KubeEdge cloud control plane (${packageName} ${packageVersion})";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/cloudcore";
              arguments = [
                "--config"
                (resultOf "configuration" "execution-path")
              ];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_delay_millis = 5000;
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        after = [(resultOf "network" "readiness-resource")];
        before = [];
        requires = [];
        wants = [(resultOf "network" "readiness-resource")];
      };
      directories.managed = [
        {
          path = "aos-pkg-cloudcore";
          purpose = "state";
          mode = "0700";
          retention = "persistent";
        }
        {
          path = "aos-pkg-cloudcore";
          purpose = "runtime";
          mode = "0750";
          retention = "restart";
        }
        {
          path = "cloudcore";
          purpose = "logs";
          mode = "0750";
          retention = "persistent";
        }
      ];
      configuration.views = [
        {
          name = "configuration";
          source = resultOf "configuration" "execution-path";
          optional = false;
        }
      ];
      credentials.views =
        lib.mapAttrsToList (name: _: {
          inherit name;
          reference = credentialPath name;
          encrypted = false;
          optional = true;
        })
        configuredCredentials;
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = ["cloudcore"];
        directory_mode = "0750";
      };
      identity = {
        supplementary_groups = [];
        ephemeral = true;
        file_creation_mask = "0077";
      };
      isolation = {
        privilege = "unprivileged";
        filesystem = "read-only-system";
        network = "host";
        process_visibility = "private";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [];
        permit_core_dumps = false;
      };
      linux_isolation = {
        allow_privilege_escalation = false;
        ambient_capabilities = [];
        capability_bounds = {
          kind = "restricted";
          capabilities = [];
        };
        control_group_delegation = false;
        control_group_access = "read-only";
        device_namespace = "private";
        kernel_clock_mutation = false;
        kernel_hostname_mutation = false;
        kernel_log_access = false;
        kernel_module_access = false;
        kernel_tunable_access = false;
        lock_personality = true;
        memory_write_execute = false;
        namespace_isolation = [];
        network_address_families = [
          "ipv4"
          "ipv6"
          "unix"
        ];
        oom_score_adjust = 0;
        permit_realtime = false;
        permit_suid_sgid = false;
        process_visibility = "self";
        syscall_architectures = ["native"];
        syscall_allow = [];
        syscall_deny = [];
        syscall_profile = "system-service";
        user_namespace_ownership = "none";
      };
    };
  };
  fragments = [
    network
    configuration
    credentialSources
    credentialDeliveries
    service
  ];
  contributions = map serviceManagement.splitContribution fragments;
in {
  options.cloudcore = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned KubeEdge CloudCore service.";
    };
    advertiseAddresses = mkOption {
      type = abilityTypes.list {
        element = address;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      default = ["127.0.0.1"];
      description = "Addresses advertised to EdgeCore nodes.";
    };
    monitorAddress = mkOption {
      type = nonWhitespace;
      default = "127.0.0.1:9091";
      description = "CloudCore metrics listener address.";
    };
    nodeLimit = mkOption {
      type = positiveInt;
      default = 1000;
      description = "Maximum simultaneously connected edge nodes.";
    };
    kubeApi = {
      kubeconfig = mkOption {
        type = secretRef "Opaque Kubernetes API kubeconfig reference.";
        default = {};
        description = "Opaque credential reference for CloudCore's Kubernetes API kubeconfig.";
      };
      qps = mkOption {
        type = positiveInt;
        default = 2500;
        description = "Kubernetes API request rate.";
      };
      burst = mkOption {
        type = positiveInt;
        default = 5000;
        description = "Kubernetes API request burst limit.";
      };
    };
    https = {
      enable = mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Enable CloudHub's HTTPS enrollment listener.";
      };
      address = mkOption {
        type = address;
        default = "0.0.0.0";
        description = "Address on which CloudHub accepts HTTPS enrollment requests.";
      };
      port = mkOption {
        type = port;
        default = 10002;
        readOnly = true;
        description = "Signed HTTPS port admitted by the CloudCore expose firewall contract.";
      };
    };
    websocket = {
      enable = mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Enable CloudHub's WebSocket listener for connected edge nodes.";
      };
      address = mkOption {
        type = address;
        default = "0.0.0.0";
        description = "Address on which CloudHub accepts WebSocket connections from edge nodes.";
      };
      port = mkOption {
        type = port;
        default = 10000;
        readOnly = true;
        description = "Signed WebSocket port admitted by the CloudCore expose firewall contract.";
      };
    };
    tls = {
      caCertificate = mkOption {
        type = secretRef "Opaque CloudCore CA certificate reference.";
        default = {};
        description = "Opaque credential reference for the CloudHub certificate authority certificate.";
      };
      caPrivateKey = mkOption {
        type = secretRef "Opaque CloudCore CA private-key reference.";
        default = {};
        description = "Opaque credential reference for the CloudHub certificate authority private key.";
      };
      serverCertificate = mkOption {
        type = secretRef "Opaque CloudCore server certificate reference.";
        default = {};
        description = "Opaque credential reference for the CloudHub server certificate.";
      };
      serverPrivateKey = mkOption {
        type = secretRef "Opaque CloudCore server private-key reference.";
        default = {};
        description = "Opaque credential reference for the CloudHub server private key.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.enable || cfg.advertiseAddresses != [];
          message = "cloudcore.enable requires at least one cloudcore.advertiseAddresses entry";
        }
        {
          assertion = !cfg.enable || builtins.all (value: value != null) requiredRefs;
          message = "cloudcore.enable requires kubeconfig and all CloudHub TLS credential references";
        }
        {
          assertion = !cfg.enable || cfg.https.enable || cfg.websocket.enable;
          message = "cloudcore.enable requires HTTPS or WebSocket CloudHub transport";
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
