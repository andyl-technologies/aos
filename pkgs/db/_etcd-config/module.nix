##! Typed runtime configuration for the package-owned etcd service.
{
  config,
  lib,
  ...
}: let
  cfg = config.etcd;
  inherit (lib) mkOption types;

  positiveInt = types.addCheck types.int (value: value > 0);
  endpoint = types.strMatching "https?://[^[:space:],]+";
  nonEmpty = types.strMatching ".+";
  memberName = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]*";
  secretRef = types.submodule ({...}: {
    config._module.strict = true;
    options.ref = mkOption {
      type = types.nullOr (types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
      default = null;
      description = "Opaque AOS credential reference; secret bytes never enter Nix evaluation.";
    };
  });
  member = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = memberName;
        default = name;
        readOnly = true;
        description = "Member name used in the initial cluster map.";
      };
      peerUrls = mkOption {
        type = types.nonEmptyListOf endpoint;
        description = "Advertised peer endpoints for this cluster member.";
      };
    };
  });
  transport = types.submodule ({...}: {
    config._module.strict = true;
    options = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Require TLS on this transport.";
      };
      certificate = mkOption {
        type = secretRef;
        default = {};
        description = "Opaque reference to the PEM certificate.";
      };
      privateKey = mkOption {
        type = secretRef;
        default = {};
        description = "Opaque reference to the PEM private key.";
      };
      trustedCa = mkOption {
        type = secretRef;
        default = {};
        description = "Opaque reference to the trusted PEM CA bundle.";
      };
      clientCertificateAuth = mkOption {
        type = types.bool;
        default = false;
        description = "Require and verify certificates presented by remote clients or peers.";
      };
    };
  });
  allUnique = values: builtins.length values == builtins.length (lib.unique values);
  allScheme = scheme: values:
    builtins.all (value: lib.hasPrefix "${scheme}://" value) values;
  clusterMembers = lib.mapAttrsToList (_: value: value) cfg.cluster.members;
  initialCluster = lib.concatStringsSep "," (
    lib.concatMap
    (memberValue: builtins.map (url: "${memberValue.name}=${url}") memberValue.peerUrls)
    clusterMembers
  );
  credentialPath = name: "/run/credentials/etcd.service/${name}";
  transportConfig = prefix: transportCfg:
    lib.optionalAttrs transportCfg.enable {
      "${prefix}-transport-security" = {
        "cert-file" = credentialPath "${prefix}-certificate";
        "key-file" = credentialPath "${prefix}-private-key";
        "trusted-ca-file" = credentialPath "${prefix}-trusted-ca";
        "client-cert-auth" = transportCfg.clientCertificateAuth;
      };
    };
  serverConfig =
    {
      name = cfg.name;
      "data-dir" = "/var/lib/aos-pkg-etcd";
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
      "metrics" = cfg.metrics;
    }
    // transportConfig "client" cfg.client.tls
    // transportConfig "peer" cfg.peer.tls;
  renderedConfig = builtins.toJSON serverConfig;
  usedCredentials =
    (lib.optionals cfg.client.tls.enable [
      ["client-certificate" cfg.client.tls.certificate.ref]
      ["client-private-key" cfg.client.tls.privateKey.ref]
      ["client-trusted-ca" cfg.client.tls.trustedCa.ref]
    ])
    ++ (lib.optionals cfg.peer.tls.enable [
      ["peer-certificate" cfg.peer.tls.certificate.ref]
      ["peer-private-key" cfg.peer.tls.privateKey.ref]
      ["peer-trusted-ca" cfg.peer.tls.trustedCa.ref]
    ]);
in {
  options.etcd = {
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
        type = types.nonEmptyListOf endpoint;
        default = ["http://127.0.0.1:2379"];
        description = "Client endpoints on which etcd listens.";
      };
      advertiseUrls = mkOption {
        type = types.nonEmptyListOf endpoint;
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
        type = types.nonEmptyListOf endpoint;
        default = ["http://127.0.0.1:2380"];
        description = "Peer endpoints on which this member listens.";
      };
      advertiseUrls = mkOption {
        type = types.nonEmptyListOf endpoint;
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
        type = types.attrsOf member;
        default.default.peerUrls = ["http://127.0.0.1:2380"];
        description = "Initial member topology keyed by stable member name.";
      };
      state = mkOption {
        type = types.enum ["new" "existing"];
        default = "new";
        description = "Whether this member creates or joins the declared cluster.";
      };
      token = mkOption {
        type = types.strMatching "[A-Za-z0-9_.-]+";
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
          type = types.enum ["periodic" "revision"];
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
      type = types.enum ["basic" "extensive"];
      default = "basic";
      description = "Prometheus metric detail exported by etcd.";
    };
  };

  config = {
    assertions = [
      {
        assertion = builtins.hasAttr cfg.name cfg.cluster.members;
        message = "etcd.cluster.members must contain the local etcd.name";
      }
      {
        assertion = !builtins.hasAttr cfg.name cfg.cluster.members || cfg.cluster.members.${cfg.name}.peerUrls == cfg.peer.advertiseUrls;
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
        assertion = !cfg.client.tls.enable || builtins.all (value: value != null) [cfg.client.tls.certificate.ref cfg.client.tls.privateKey.ref cfg.client.tls.trustedCa.ref];
        message = "etcd client TLS requires certificate, private-key, and trusted-CA references";
      }
      {
        assertion = !cfg.peer.tls.enable || builtins.all (value: value != null) [cfg.peer.tls.certificate.ref cfg.peer.tls.privateKey.ref cfg.peer.tls.trustedCa.ref];
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

    etcd.config.service = {
      ETCD_ENABLED = cfg.enable;
      ETCD_CONFIG_GENERATION = builtins.hashString "sha256" renderedConfig;
    };
    etcd.credentials = builtins.listToAttrs (builtins.map (entry: {
        name = builtins.elemAt entry 0;
        value.ref = builtins.elemAt entry 1;
      })
      usedCredentials);

    environment.etc."aos/packages/etcd/etcd.json" = {
      text = renderedConfig + "\n";
      mode = "0444";
    };
  };
}
