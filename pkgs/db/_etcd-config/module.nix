##! Package-owned etcd configuration and native service activation.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.etcd;
  inherit (lib) mkOption;
  types = lib.types;
  operations = config.aos.abilities;
  enabled = config.aos.services."etcd.main".enable;
  positiveInt = types.ints.between 1 9007199254740991;
  endpoint = types.strMatching "https?://[^[:space:],]+";
  nonEmpty = types.strMatching ".+";
  memberName = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]*";
  clusterToken = types.strMatching "[A-Za-z0-9_.-]+";
  clusterStateType = types.enum ["new" "existing"];
  compactionModeType = types.enum ["periodic" "revision"];
  metricsType = types.enum ["basic" "extensive"];
  credentialReference = types.submodule operations.credential.operations.deliver.input;
  credentialConfigured = value: (value.name != null) != (value.resource != null);
  endpointList = types.listOf endpoint;
  member = types.submodule {options.peerUrls = mkOption {type = endpointList;};};
  members = types.attrsOf member;
  transport = types.submodule {
    options = {
      enable = mkOption {
        type = types.bool;
        default = false;
      };
      certificate = mkOption {
        type = credentialReference;
        default = {};
      };
      privateKey = mkOption {
        type = credentialReference;
        default = {};
      };
      trustedCa = mkOption {
        type = credentialReference;
        default = {};
      };
      clientCertificateAuth = mkOption {
        type = types.bool;
        default = false;
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
  credentialPath = name: operations.credential.operations.deliver.effects."etcd-${name}".outputs.path;
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
      "data-dir" = operations.filesystem.operations.directory.effects.etcd-data.outputs.path;
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
        reference = cfg.client.tls.certificate;
      }
      {
        name = "client-private-key";
        reference = cfg.client.tls.privateKey;
      }
      {
        name = "client-trusted-ca";
        reference = cfg.client.tls.trustedCa;
      }
    ])
    ++ (lib.optionals peerTls [
      {
        name = "peer-certificate";
        reference = cfg.peer.tls.certificate;
      }
      {
        name = "peer-private-key";
        reference = cfg.peer.tls.privateKey;
      }
      {
        name = "peer-trusted-ca";
        reference = cfg.peer.tls.trustedCa;
      }
    ]);
  command = arguments: {
    executable = {
      path = "${package}/bin/etcd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  usedCredentials = credentialsFor cfg.client.tls.enable cfg.peer.tls.enable;
  serviceDefinition = {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = [];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "shared";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = true;
      writable_executable_memory = false;
      isolation_domains = [];
      network_families = ["ipv4" "ipv6" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      security_label = "aos-pkg-etcd";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "return-permission-denied";
      operation_profile = "restricted";
      isolated_identity_mapping = "none";
    };
    service = "etcd";
    lifecycle = {
      description = "etcd distributed key-value store";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command ["--config-file" (operations.configuration.operations.file.effects.etcd.outputs.path)])];
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
      after = [(operations.network.operations.ready.effects.etcd.outputs.resource)];
      before = [];
      requires = [];
      wants = [(operations.network.operations.ready.effects.etcd.outputs.resource)];
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
            inherit (credential) name;
            inherit (credential.reference) encrypted;
            reference = credentialPath credential.name;
            optional = false;
          })
          usedCredentials;
      };
    configuration.views = [
      {
        name = "server";
        source = operations.configuration.operations.file.effects.etcd.outputs.path;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "data";
        source = operations.filesystem.operations.directory.effects.etcd-data.outputs.path;
        access = "read-write";
      }
      {
        name = "runtime";
        source = operations.filesystem.operations.directory.effects.etcd-runtime.outputs.path;
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
  };
in {
  options.aos.etcd = {
    enable = mkOption {
      type = types.bool;
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
        type = types.bool;
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
  };

  config = lib.mkMerge [
    {
      assertions =
        [
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
            assertion =
              !cfg.client.tls.enable
              || builtins.all credentialConfigured [
                cfg.client.tls.certificate
                cfg.client.tls.privateKey
                cfg.client.tls.trustedCa
              ];
            message = "etcd client TLS requires certificate, private-key, and trusted-CA references";
          }
          {
            assertion =
              !cfg.peer.tls.enable
              || builtins.all credentialConfigured [
                cfg.peer.tls.certificate
                cfg.peer.tls.privateKey
                cfg.peer.tls.trustedCa
              ];
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
        ]
        ++ [
          {
            assertion = builtins.all (value: builtins.match "[A-Za-z0-9][A-Za-z0-9_.-]*" value != null) (builtins.attrNames cfg.cluster.members);
            message = "etcd cluster member names must be valid member identifiers";
          }
          {
            assertion = builtins.all (value: value != []) [cfg.client.listenUrls cfg.client.advertiseUrls cfg.peer.listenUrls cfg.peer.advertiseUrls];
            message = "etcd endpoint collections must be nonempty";
          }
        ];
      aos.services."etcd.main" = lib.mkDefault (serviceDefinition // {enable = lib.mkDefault cfg.enable;});
    }
    (lib.mkIf enabled {
      aos.abilities = {
        filesystem.operations.directory.effects = {
          etcd-data = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-pkg-etcd";
              mode = "0700";
            };
          };
          etcd-runtime.input = {
            path = "/run/aos-pkg-etcd";
            mode = "0750";
          };
        };
        network.operations.ready.effects.etcd.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        configuration.operations.file.effects.etcd.input = {
          path = "/etc/aos/packages/etcd/etcd.json";
          format = "json";
          value = serverConfigFor cfg.client.tls.enable cfg.peer.tls.enable;
          mode = "0440";
        };
        credential.operations.deliver.effects = builtins.listToAttrs (builtins.map (credential: {
            name = "etcd-${credential.name}";
            value.input = credential.reference;
          })
          usedCredentials);
      };
    })
  ];
}
