##! Typed runtime configuration for the package-owned etcd service.
{
  config,
  lib,
  ...
}: let
  cfg = config.etcd;
  inherit (lib) mkOption;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = 9007199254740991;
  };
  endpoint = abilityTypes.refined {
    name = "etcd endpoint";
    description = "an HTTP or HTTPS endpoint without whitespace or commas";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "https?://[^[:space:],]+" value != null;
  };
  nonEmpty = abilityTypes.refined {
    name = "non-empty etcd value";
    description = "a non-empty etcd configuration value";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match ".+" value != null;
  };
  memberName = abilityTypes.refined {
    name = "etcd member name";
    description = "an etcd member name beginning with an alphanumeric character";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[A-Za-z0-9][A-Za-z0-9_.-]*" value != null;
  };
  clusterToken = abilityTypes.refined {
    name = "etcd cluster token";
    description = "an etcd cluster token containing alphanumerics, dots, underscores, or dashes";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[A-Za-z0-9_.-]+" value != null;
  };
  clusterStateType = abilityTypes.enum ["new" "existing"];
  compactionModeType = abilityTypes.enum ["periodic" "revision"];
  metricsType = abilityTypes.enum ["basic" "extensive"];
  secretRef = abilityTypes.record {
    fields = {
      resource = {
        type = abilityTypes.optional (abilityTypes.deferredResult abilityTypes.resourceReference);
        default = null;
        description = "Typed resource reference producing the credential without exposing secret bytes.";
      };
      encrypted = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether the referenced credential requires encrypted delivery.";
      };
    };
  };
  endpointList = abilityTypes.refined {
    name = "non-empty etcd endpoint list";
    description = "one or more etcd endpoints";
    type = abilityTypes.list {
      element = endpoint;
      maxItems = 256;
    };
    predicate = values: values != [];
  };
  member = abilityTypes.record {
    fields.peerUrls = {
      type = endpointList;
      description = "Advertised peer endpoints for this cluster member.";
    };
  };
  members = abilityTypes.refined {
    name = "etcd member map";
    description = "etcd members keyed by a valid member name";
    type = abilityTypes.map {
      keyMaxLength = abilityTypes.limits.maxStringLength;
      maxEntries = 256;
      value = member;
    };
    predicate = values:
      builtins.all memberName.check (builtins.attrNames values);
  };
  transport = abilityTypes.record {
    fields = {
      enable = {
        type = abilityTypes.boolean;
        default = false;
        description = "Require TLS on this transport.";
      };
      certificate = {
        type = secretRef;
        default = {};
        description = "Opaque reference to the PEM certificate.";
      };
      privateKey = {
        type = secretRef;
        default = {};
        description = "Opaque reference to the PEM private key.";
      };
      trustedCa = {
        type = secretRef;
        default = {};
        description = "Opaque reference to the trusted PEM CA bundle.";
      };
      clientCertificateAuth = {
        type = abilityTypes.boolean;
        default = false;
        description = "Require and verify certificates presented by remote clients or peers.";
      };
    };
  };
  allUnique = values: builtins.length values == builtins.length (lib.unique values);
  allScheme = scheme: values:
    builtins.all (value: lib.hasPrefix "${scheme}://" value) values;
  clusterMembers = lib.mapAttrsToList (name: value: value // {inherit name;}) cfg.cluster.members;
  localMembers = builtins.filter (memberValue: memberValue.name == cfg.name) clusterMembers;
  localMember =
    if builtins.length localMembers == 1
    then builtins.head localMembers
    else null;
  initialCluster = lib.concatStringsSep "," (
    lib.concatMap
    (memberValue: builtins.map (url: "${memberValue.name}=${url}") memberValue.peerUrls)
    clusterMembers
  );
  credentialPath = name: resultOf "credential-${name}" "credential-path";
  transportConfig = enabled: prefix: transportCfg:
    lib.optionalAttrs enabled {
      "${prefix}-transport-security" = {
        "cert-file" = credentialPath "${prefix}-certificate";
        "key-file" = credentialPath "${prefix}-private-key";
        "trusted-ca-file" = credentialPath "${prefix}-trusted-ca";
        "client-cert-auth" = transportCfg.clientCertificateAuth;
      };
    };
  serverConfigFor = clientTls: peerTls:
    {
      name = cfg.name;
      "data-dir" = resultOf "data-storage" "storage-path";
      "listen-client-urls" = lib.concatStringsSep "," cfg.client.listenUrls;
      "advertise-client-urls" = lib.concatStringsSep "," cfg.client.advertiseUrls;
      "listen-peer-urls" = lib.concatStringsSep "," cfg.peer.listenUrls;
      "initial-advertise-peer-urls" = lib.concatStringsSep "," cfg.peer.advertiseUrls;
      "initial-cluster" = initialCluster;
      "initial-cluster-state" = cfg.cluster.state;
      "initial-cluster-token" = cfg.cluster.token;
      "quota-backend-bytes" = cfg.storage.quotaBackendBytes;
      "snapshot-count" = cfg.storage.snapshotCount;
      "auto-compaction-mode" = cfg.storage.autoCompaction.mode;
      "auto-compaction-retention" = cfg.storage.autoCompaction.retention;
      "enable-grpc-gateway" = cfg.client.enableGrpcGateway;
      metrics = cfg.metrics;
    }
    // transportConfig clientTls "client" cfg.client.tls
    // transportConfig peerTls "peer" cfg.peer.tls;
  credentialsFor = clientTls: peerTls:
    (lib.optionals clientTls [
      {
        name = "client-certificate";
        inherit (cfg.client.tls.certificate) resource encrypted;
      }
      {
        name = "client-private-key";
        inherit (cfg.client.tls.privateKey) resource encrypted;
      }
      {
        name = "client-trusted-ca";
        inherit (cfg.client.tls.trustedCa) resource encrypted;
      }
    ])
    ++ (lib.optionals peerTls [
      {
        name = "peer-certificate";
        inherit (cfg.peer.tls.certificate) resource encrypted;
      }
      {
        name = "peer-private-key";
        inherit (cfg.peer.tls.privateKey) resource encrypted;
      }
      {
        name = "peer-trusted-ca";
        inherit (cfg.peer.tls.trustedCa) resource encrypted;
      }
    ]);
  runtimeString = abilityTypes.runtimeString;
  transportConfigType = abilityTypes.record {
    fields = {
      "cert-file" = abilityTypes.deferredResult runtimeString;
      "key-file" = abilityTypes.deferredResult runtimeString;
      "trusted-ca-file" = abilityTypes.deferredResult runtimeString;
      "client-cert-auth" = abilityTypes.boolean;
    };
  };
  serverConfigType = abilityTypes.record {
    fields = {
      name = memberName;
      "data-dir" = abilityTypes.deferredResult runtimeString;
      # URL collections become the comma-delimited scalar syntax etcd accepts;
      # their package options validate each endpoint before this encoding step.
      "listen-client-urls" = runtimeString;
      "advertise-client-urls" = runtimeString;
      "listen-peer-urls" = runtimeString;
      "initial-advertise-peer-urls" = runtimeString;
      "initial-cluster" = runtimeString;
      "initial-cluster-state" = clusterStateType;
      "initial-cluster-token" = clusterToken;
      "quota-backend-bytes" = positiveInt;
      "snapshot-count" = positiveInt;
      "auto-compaction-mode" = compactionModeType;
      "auto-compaction-retention" = nonEmpty;
      "enable-grpc-gateway" = abilityTypes.boolean;
      metrics = metricsType;
      "client-transport-security" = {
        type = abilityTypes.optional transportConfigType;
        optional = true;
      };
      "peer-transport-security" = {
        type = abilityTypes.optional transportConfigType;
        optional = true;
      };
    };
  };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/etcd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  abilityFragmentsFor = clientTls: peerTls: let
    usedCredentials = credentialsFor clientTls peerTls;
    producer = key: interface: parameters:
      serviceManagement.forProducer {
        consumerInstance = "etcd";
        inherit key interface parameters;
      };
    dataStorage = producer "data-storage" serviceManagement.interfaces.persistentStorageAllocation {
      name = "data";
      purpose = "state";
      mode = "0700";
    };
    runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
      name = "runtime";
      purpose = "runtime";
      mode = "0750";
    };
    networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
      scope = "configured-connectivity";
      address_families = ["ipv4" "ipv6"];
    };
    credentialRequests = serviceManagement.forProducers {
      consumerInstance = "etcd";
      interface = serviceManagement.interfaces.credentialDelivery;
      producers =
        builtins.map (credential: {
          key = "credential-${credential.name}";
          parameters = {
            inherit (credential) name encrypted;
            source = credential.resource;
          };
        })
        usedCredentials;
    };
    configurationRequest = serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "etcd";
      declaration = {
        name = "server-configuration";
        source = serviceManagement.structuredSource {
          format = "json";
          valueType = serverConfigType;
          value = serverConfigFor clientTls peerTls;
        };
        mode = "0440";
      };
    };
    serviceRequest = serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "etcd";
      declaration = {
        service = "main";
        enabled = true;
        lifecycle = {
          description = "etcd distributed key-value store";
          execution_model = "foreground";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [(command ["--config-file" (resultOf "server-configuration" "planned-path")])];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "on-failure";
          restart_token = cfg.restartToken;
          restart_delay_millis = 5000;
          remain_after_exit = false;
          start_timeout_millis = 90000;
          stop_timeout_millis = 90000;
        };
        dependencies = {
          after = [(resultOf "network-readiness" "readiness-resource")];
          before = [];
          requires = [];
          wants = [(resultOf "network-readiness" "readiness-resource")];
        };
        readiness = {
          mechanism = "process-signal";
          signal_scope = "all-processes";
          timeout_millis = 90000;
        };
        credentials =
          if usedCredentials == []
          then null
          else {
            views =
              builtins.map (credential: {
                inherit (credential) name encrypted;
                reference = resultOf "credential-${credential.name}" "credential-path";
                optional = false;
              })
              usedCredentials;
          };
        configuration.views = [
          {
            name = "server";
            source = resultOf "server-configuration" "planned-path";
            optional = false;
          }
        ];
        storage.mounts = [
          {
            name = "data";
            source = resultOf "data-storage" "planned-path";
            access = "read-write";
          }
          {
            name = "runtime";
            source = resultOf "runtime-storage" "planned-path";
            access = "read-write";
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
          ephemeral = true;
          file_creation_mask = "0077";
        };
        isolation = {
          privilege = "unprivileged";
          filesystem = "read-only-system";
          network = "host";
          process_visibility = "host";
          termination_scope = "all-processes";
          temporary_directory = "private";
          devices = [];
          host_paths = [];
          permit_core_dumps = false;
        };
        resources.open_files = {
          kind = "maximum";
          value = 1048576;
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
          device_namespace = "shared";
          kernel_clock_mutation = false;
          kernel_hostname_mutation = false;
          kernel_log_access = false;
          kernel_module_access = false;
          kernel_tunable_access = false;
          lock_personality = true;
          memory_write_execute = false;
          namespace_isolation = [];
          network_address_families = ["ipv4" "ipv6" "unix"];
          oom_score_adjust = 0;
          permit_realtime = false;
          permit_suid_sgid = false;
          process_visibility = "all";
          security_label = "aos-pkg-etcd";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "restricted";
          user_namespace_ownership = "none";
        };
      };
    };
  in [dataStorage runtimeStorage networkReadiness configurationRequest credentialRequests serviceRequest];
  staticAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).declarations)
    (abilityFragmentsFor true true);
  configuredAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).configured)
    (abilityFragmentsFor cfg.client.tls.enable cfg.peer.tls.enable);
in {
  options.etcd = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned etcd service.";
    };
    name = mkOption {
      type = memberName;
      default = "default";
      description = "Stable name of this etcd member.";
    };
    client = {
      listenUrls = mkOption {
        type = endpointList;
        default = ["http://127.0.0.1:2379"];
        description = "Client endpoints on which etcd listens.";
      };
      advertiseUrls = mkOption {
        type = endpointList;
        default = ["http://127.0.0.1:2379"];
        description = "Client endpoints advertised to clients and peers.";
      };
      enableGrpcGateway = mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Enable the embedded gRPC-to-JSON gateway.";
      };
      tls = mkOption {
        type = transport;
        default = {};
        description = "TLS policy and opaque credential references for client traffic.";
      };
    };
    peer = {
      listenUrls = mkOption {
        type = endpointList;
        default = ["http://127.0.0.1:2380"];
        description = "Peer endpoints on which this member listens.";
      };
      advertiseUrls = mkOption {
        type = endpointList;
        default = ["http://127.0.0.1:2380"];
        description = "Peer endpoints advertised to the other members.";
      };
      tls = mkOption {
        type = transport;
        default = {};
        description = "Mutual-TLS policy and opaque credential references for replication traffic.";
      };
    };
    cluster = {
      members = mkOption {
        type = members;
        default.default.peerUrls = ["http://127.0.0.1:2380"];
        description = "Initial member topology keyed by stable member name.";
      };
      state = mkOption {
        type = clusterStateType;
        default = "new";
        description = "Whether this member creates or joins the declared cluster.";
      };
      token = mkOption {
        type = clusterToken;
        default = "aos-etcd-cluster";
        description = "Non-secret identifier preventing accidental cross-cluster joins.";
      };
    };
    storage = {
      quotaBackendBytes = mkOption {
        type = positiveInt;
        default = 2147483648;
        description = "Maximum backend database size in bytes before writes are alarmed.";
      };
      snapshotCount = mkOption {
        type = positiveInt;
        default = 100000;
        description = "Committed transactions between Raft snapshots.";
      };
      autoCompaction = {
        mode = mkOption {
          type = compactionModeType;
          default = "periodic";
          description = "Automatic history compaction mode.";
        };
        retention = mkOption {
          type = nonEmpty;
          default = "1h";
          description = "History retention interpreted according to the compaction mode.";
        };
      };
    };
    metrics = mkOption {
      type = metricsType;
      default = "basic";
      description = "Prometheus metric detail exported by etcd.";
    };
    restartToken = mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Optional operator token that forces lifecycle reconciliation when changed.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = localMember != null;
          message = "etcd.cluster.members must contain the local etcd.name";
        }
        {
          assertion = localMember == null || localMember.peerUrls == cfg.peer.advertiseUrls;
          message = "the local etcd cluster member peerUrls must equal etcd.peer.advertiseUrls";
        }
        {
          assertion = allUnique cfg.client.listenUrls && allUnique cfg.client.advertiseUrls;
          message = "etcd client endpoint lists must not contain duplicates";
        }
        {
          assertion = allUnique cfg.peer.listenUrls && allUnique cfg.peer.advertiseUrls;
          message = "etcd peer endpoint lists must not contain duplicates";
        }
        {
          assertion = !cfg.client.tls.enable || (allScheme "https" cfg.client.listenUrls && allScheme "https" cfg.client.advertiseUrls);
          message = "etcd client endpoints must all use HTTPS when client TLS is enabled";
        }
        {
          assertion = cfg.client.tls.enable || (allScheme "http" cfg.client.listenUrls && allScheme "http" cfg.client.advertiseUrls);
          message = "etcd client endpoints must all use HTTP when client TLS is disabled";
        }
        {
          assertion = !cfg.peer.tls.enable || (allScheme "https" cfg.peer.listenUrls && allScheme "https" cfg.peer.advertiseUrls);
          message = "etcd peer endpoints must all use HTTPS when peer TLS is enabled";
        }
        {
          assertion = cfg.peer.tls.enable || (allScheme "http" cfg.peer.listenUrls && allScheme "http" cfg.peer.advertiseUrls);
          message = "etcd peer endpoints must all use HTTP when peer TLS is disabled";
        }
        {
          assertion = !cfg.client.tls.enable || builtins.all (value: value != null) [(cfg.client.tls.certificate.resource or null) (cfg.client.tls.privateKey.resource or null) (cfg.client.tls.trustedCa.resource or null)];
          message = "etcd client TLS requires certificate, private-key, and trusted-CA references";
        }
        {
          assertion = !cfg.peer.tls.enable || builtins.all (value: value != null) [(cfg.peer.tls.certificate.resource or null) (cfg.peer.tls.privateKey.resource or null) (cfg.peer.tls.trustedCa.resource or null)];
          message = "etcd peer TLS requires certificate, private-key, and trusted-CA references";
        }
        {
          assertion = builtins.all (memberValue: allUnique memberValue.peerUrls) clusterMembers;
          message = "each etcd cluster member must advertise unique peer endpoints";
        }
        {
          assertion = builtins.all (memberValue:
            allScheme (
              if cfg.peer.tls.enable
              then "https"
              else "http"
            )
            memberValue.peerUrls)
          clusterMembers;
          message = "all etcd cluster member peer endpoints must follow the configured peer TLS scheme";
        }
        {
          assertion =
            if cfg.storage.autoCompaction.mode == "revision"
            then builtins.match "[1-9][0-9]*" cfg.storage.autoCompaction.retention != null
            else builtins.match "[1-9][0-9]*(ms|s|m|h)" cfg.storage.autoCompaction.retention != null;
          message = "etcd auto-compaction retention must be a positive revision or duration matching its mode";
        }
      ];
    }
    (lib.mkMerge (builtins.map
      (fragment: {aos.abilities = fragment;})
      staticAbilityFragments))
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.etcd = {};}]
        ++ configuredAbilityFragments
      );
    })
  ];
}
