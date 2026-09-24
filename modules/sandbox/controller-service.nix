##! modules/sandbox/controller-service.nix — production unprivileged controller
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.controllerService;
  controller = config.aos.sandbox.controller;
  brokers = config.aos.sandbox;
  ownershipAuthority =
    brokers.ownershipAuthority or {
      enable = false;
      credentials.sessionKey = null;
    };
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  brokerSessionEndpoints = map (endpoint:
    endpoint
    // {
      role = "client";
      required = true;
      description = "controller-to-${endpoint.name}";
      options = {
        manifest = "brokerSession${endpoint.optionName}Manifest";
        hello = "brokerSession${endpoint.optionName}HelloKey";
        record = "brokerSession${endpoint.optionName}RecordKey";
      };
    }) [
    {
      name = "host";
      optionName = "Host";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/host";
    }
    {
      name = "storage";
      optionName = "Storage";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/storage";
    }
    {
      name = "mount";
      optionName = "Mount";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/mount";
    }
    {
      name = "network";
      optionName = "Network";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/network";
    }
  ];
  brokerSessionConfiguration = brokerSession.configure cfg.credentials brokerSessionEndpoints;
  nodeCredentials =
    lib.optional (cfg.credentials.nodeId != null)
    "node-id:/run/credentials/@system/${cfg.credentials.nodeId}";
  cacheReplayCredentials =
    lib.optional (cfg.credentials.cacheReplayBundle != null)
    "cache-replay-bundle:/run/credentials/@system/${cfg.credentials.cacheReplayBundle}";
  cacheReadbackCredentials = lib.optionals (cfg.credentials.cacheOwnerReadbackSigningKey != null && cfg.credentials.cacheOwnerReadbackPublicKey != null) [
    "cache-owner-readback-signing-key:/run/credentials/@system/${cfg.credentials.cacheOwnerReadbackSigningKey}"
    "cache-owner-readback-public-key:/run/credentials/@system/${cfg.credentials.cacheOwnerReadbackPublicKey}"
  ];
  guestRootTemplateCredentials = [
    "guest-root-package-binding-v1:${pkgs.aos-sandbox-guest-root-template}/package-binding"
    "guest-root-tree-digest-v1:${pkgs.aos-sandbox-guest-root-template}/root-tree-digest"
  ];
  brokerPlanCredentials = lib.optionals (cfg.credentials.brokerPlanSigningKey != null) (
    ["broker-plan-signing-key:/run/credentials/@system/${cfg.credentials.brokerPlanSigningKey}"]
    ++ lib.optional (brokers.hostBroker.credentials.brokerPlanPolicy != null)
    "broker-plan-policy.cbor:/run/credentials/@system/${brokers.hostBroker.credentials.brokerPlanPolicy}"
    ++ lib.optional (brokers.hostBroker.credentials.brokerPlanPublicKey != null)
    "broker-plan-public-key:/run/credentials/@system/${brokers.hostBroker.credentials.brokerPlanPublicKey}"
    ++ lib.optional (brokers.hostBroker.credentials.brokerRevocationScope != null)
    "broker-revocation-scope:/run/credentials/@system/${brokers.hostBroker.credentials.brokerRevocationScope}"
  );
  mountPlanCredentials = lib.optionals (cfg.credentials.brokerPlanSigningKey != null) (
    lib.optional (brokers.mountBroker.credentials.brokerPlanPolicy != null)
    "mount-broker-plan-policy.cbor:/run/credentials/@system/${brokers.mountBroker.credentials.brokerPlanPolicy}"
    ++ lib.optional (brokers.mountBroker.credentials.brokerPlanPublicKey != null)
    "mount-broker-plan-public-key:/run/credentials/@system/${brokers.mountBroker.credentials.brokerPlanPublicKey}"
    ++ lib.optional (brokers.mountBroker.credentials.brokerRevocationScope != null)
    "mount-broker-revocation-scope:/run/credentials/@system/${brokers.mountBroker.credentials.brokerRevocationScope}"
  );
  attachTrustCredential = brokers.hostBroker.credentials.opensshAttachTrust or null;
  attachGrantPublicKeyCredential = brokers.hostBroker.credentials.opensshAttachGrantPublicKey or null;
  opensshAttachCredentials = lib.optionals (cfg.credentials.opensshAttachGrantSigningKey != null) (
    ["openssh-attach-grant-signing-key:/run/credentials/@system/${cfg.credentials.opensshAttachGrantSigningKey}"]
    ++ lib.optional (cfg.credentials.opensshAttachCaSigningKey != null)
    "openssh-attach-ca-signing-key:/run/credentials/@system/${cfg.credentials.opensshAttachCaSigningKey}"
    ++ lib.optional (attachTrustCredential != null)
    "openssh-attach-trust.json:/run/credentials/@system/${attachTrustCredential}"
    ++ lib.optional (attachGrantPublicKeyCredential != null)
    "openssh-attach-grant-public-key:/run/credentials/@system/${attachGrantPublicKeyCredential}"
  );
  ownershipCredentials = lib.optionals ownershipAuthority.enable (
    lib.optional (ownershipAuthority.credentials.sessionKey != null)
    "ownership-session-key:/run/credentials/@system/${ownershipAuthority.credentials.sessionKey}"
    ++ lib.optional (brokers.hostBroker.credentials.ownershipLeasePolicy != null)
    "ownership-lease-policy.cbor:/run/credentials/@system/${brokers.hostBroker.credentials.ownershipLeasePolicy}"
    ++ lib.optional (brokers.hostBroker.credentials.ownershipLeasePublicKey != null)
    "ownership-lease-public-key:/run/credentials/@system/${brokers.hostBroker.credentials.ownershipLeasePublicKey}"
  );
  publicCredentialNames = {
    publicApiServerCert = "public-api-server-cert";
    publicApiServerKey = "public-api-server-key";
    publicApiClientCa = "public-api-client-ca";
    publicApiPrincipals = "public-api-principals";
  };
  publicCredentials = lib.optionals cfg.publicApi.enable (
    lib.mapAttrsToList (option: name: "${name}:/run/credentials/@system/${cfg.credentials.${option}}")
    (lib.filterAttrs (option: _: cfg.credentials.${option} != null) publicCredentialNames)
  );
  bootstrapCredentials = lib.optionals (cfg.publicApi.enable && cfg.credentials.publicApiEntitlements != null) [
    "public-api-entitlements:/run/credentials/@system/${cfg.credentials.publicApiEntitlements}"
    "public-api-entitlement-public-key:/run/credentials/@system/${cfg.credentials.publicApiEntitlementPublicKey}"
  ];
  operatorRecoveryCredentials = lib.optionals (cfg.credentials.operatorRecoveryControllerKey != null) [
    "operator-recovery-controller-key-v1:/run/credentials/@system/${cfg.credentials.operatorRecoveryControllerKey}"
    "operator-recovery-storage-owner-key-v1:/run/credentials/@system/${cfg.credentials.operatorRecoveryStorageOwnerPublicKey}"
  ];
  publisherScopeCredential =
    lib.optional cfg.publisherIngress.enable
    "publisher-service-scope-v1:/run/credentials/@system/${cfg.credentials.publisherServiceScope}";
  publisherPolicySourceCredentials = lib.optionals cfg.publisherIngress.enable [
    "publisher-policy-source-v1:/run/credentials/@system/${cfg.credentials.publisherPolicySource}"
    "publisher-policy-v1.cbor:/run/credentials/@system/${cfg.credentials.publisherPolicy}"
    "publisher-policy-source-public-key-v1:/run/credentials/@system/${cfg.credentials.publisherPolicySourcePublicKey}"
  ];
in {
  options.aos.sandbox.controllerService = {
    enable = lib.mkEnableOption "the production unprivileged sandbox node controller";

    publicApi.enable = lib.mkEnableOption "the registered mutual-TLS controller API on /run/aos/sandboxd/public.sock";

    publisherIngress.enable = lib.mkEnableOption "the exact-process project publisher registration channel; publication effects remain unavailable";

    publisherIngress.uid = lib.mkOption {
      type = lib.types.int;
      default = 991;
      description = "Dedicated networkless publisher service UID, matched to the protected scope credential.";
    };

    publisherIngress.gid = lib.mkOption {
      type = lib.types.int;
      default = 991;
      description = "Dedicated networkless publisher service GID, matched to the protected scope credential.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The independently packaged unprivileged controller executable.";
    };

    credentials =
      {
        nodeId = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External system credential containing the raw nonzero 16-byte node identity.";
        };
        brokerPlanSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional external 32-byte controller broker-plan signing seed for authority publications and Guardian arm plans.";
        };
        opensshAttachGrantSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional external 32-byte seed for the dedicated signed public OpenSSH attach pending grant.";
        };
        opensshAttachCaSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional external Ed25519 OpenSSH user CA private key for authorized attachment certificate issuance.";
        };
        cacheReplayBundle = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional protected canonical cache Replay bundle; required for clean cache bootstrap unless the controller source journal was provisioned earlier.";
        };
        cacheOwnerReadbackSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional separate-purpose 32-byte Cache owner readback signing seed; no Create publication consumes it.";
        };
        cacheOwnerReadbackPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional matching 80-byte AOSCPK01 Cache readback pin for local seed verification.";
        };
        publisherServiceScope = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External 64-byte AOSPMS01 scope: principal, project, cache resource, publisher UID/GID; never derived from socket credentials.";
        };
        publisherPolicySource = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External 272-byte signed AOSPSC01 initial publisher-policy source, bound to the publisher principal, node, project, and cache resource.";
        };
        publisherPolicy = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Exact canonical publisher policy CBOR committed by the signed AOSPSC01 source.";
        };
        publisherPolicySourcePublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Dedicated 32-byte Ed25519 verifier for the publisher-policy source.";
        };
        publicApiEntitlements = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional signed canonical principal-specific first-capability entitlements; bootstrap stays closed when absent.";
        };
        publicApiEntitlementPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Dedicated externally provisioned Ed25519 verifier for first-capability entitlements.";
        };
        operatorRecoveryControllerKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Dedicated AOSORCK1 Ed25519 controller Repair signing record; null keeps public Repair closed.";
        };
        operatorRecoveryStorageOwnerPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Independently provisioned AOSORSK1 Storage owner public-key record for Repair receipts.";
        };
      }
      // brokerSession.mkOptions brokerSessionEndpoints
      // lib.mapAttrs (_: name:
        lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External protected credential loaded as ${name} for the public TLS endpoint.";
        })
      publicCredentialNames;
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = cfg.credentials.nodeId != null;
          message = "aos.sandbox.controllerService.credentials.nodeId is required";
        }
        {
          assertion =
            (cfg.credentials.cacheOwnerReadbackSigningKey == null)
            == (cfg.credentials.cacheOwnerReadbackPublicKey == null);
          message = "Cache owner readback signing seed and role-specific public pin must be provisioned together";
        }
        {
          assertion =
            cfg.credentials.cacheOwnerReadbackSigningKey
            == null
            || (config.aos.sandbox.policyAuthority.enable
              && config.aos.sandbox.policyAuthority.credentials.cacheOwnerReadbackPublicKey
              == cfg.credentials.cacheOwnerReadbackPublicKey);
          message = "Cache owner readback requires the policy authority to load the same fixed public pin credential";
        }
        {
          assertion = (cfg.credentials.operatorRecoveryControllerKey == null) == (cfg.credentials.operatorRecoveryStorageOwnerPublicKey == null);
          message = "controller operator Recovery signing and Storage owner trust credentials must be provisioned together";
        }
        {
          assertion = !cfg.publisherIngress.enable || cfg.credentials.publisherServiceScope != null;
          message = "publisher ingress requires an externally provisioned publisherServiceScope credential";
        }
        {
          assertion =
            !cfg.publisherIngress.enable
            || (cfg.credentials.publisherPolicySource
              != null
              && cfg.credentials.publisherPolicy != null
              && cfg.credentials.publisherPolicySourcePublicKey != null);
          message = "publisher ingress requires signed publisher policy source, canonical policy, and dedicated verification key credentials";
        }
        {
          assertion = !cfg.publisherIngress.enable || (cfg.publisherIngress.uid > 0 && cfg.publisherIngress.uid < 65536 && cfg.publisherIngress.gid > 0 && cfg.publisherIngress.gid < 65536);
          message = "publisher ingress UID and GID must be within 1..65535";
        }
        {
          assertion = !cfg.publisherIngress.enable || (cfg.publisherIngress.uid != controller.uid && cfg.publisherIngress.gid != controller.gid);
          message = "publisher execution must not share the controller UID or GID";
        }
        {
          assertion = brokers.hostBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.hostBroker";
        }
        {
          assertion =
            cfg.credentials.brokerPlanSigningKey
            == null
            || (
              brokers.hostBroker.credentials.brokerPlanPolicy
              != null
              && brokers.hostBroker.credentials.brokerPlanPublicKey != null
              && brokers.hostBroker.credentials.brokerRevocationScope != null
            );
          message = "aos.sandbox.controllerService broker-plan signing requires the Host broker's public plan policy, key, and revocation scope";
        }
        {
          assertion =
            (cfg.credentials.opensshAttachGrantSigningKey
              == null
              && cfg.credentials.opensshAttachCaSigningKey == null
              && attachTrustCredential == null
              && attachGrantPublicKeyCredential == null)
            || (cfg.credentials.opensshAttachGrantSigningKey
              != null
              && cfg.credentials.opensshAttachCaSigningKey != null
              && attachTrustCredential != null
              && attachGrantPublicKeyCredential != null);
          message = "aos.sandbox.controllerService OpenSSH attach grants require the dedicated signing key and both Host attach trust credentials together";
        }
        {
          assertion =
            cfg.credentials.brokerPlanSigningKey
            == null
            || (
              brokers.mountBroker.credentials.brokerPlanPolicy
              != null
              && brokers.mountBroker.credentials.brokerPlanPublicKey != null
              && brokers.mountBroker.credentials.brokerRevocationScope != null
            );
          message = "aos.sandbox.controllerService broker-plan signing requires the Mount broker's independent public plan policy, key, and revocation scope";
        }
        {
          assertion = brokers.storageBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.storageBroker";
        }
        {
          assertion = brokers.mountBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.mountBroker";
        }
        {
          assertion = brokers.networkBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.networkBroker";
        }
        {
          assertion = !ownershipAuthority.enable || ownershipAuthority.credentials.sessionKey != null;
          message = "aos.sandbox.controllerService ownership resumption requires the ownership session key";
        }
        {
          assertion =
            !ownershipAuthority.enable
            || (
              brokers.hostBroker.credentials.ownershipLeasePolicy
              != null
              && brokers.hostBroker.credentials.ownershipLeasePublicKey != null
            );
          message = "aos.sandbox.controllerService ownership resumption requires the Host broker's lease policy and public key";
        }
      ]
      ++ brokerSessionConfiguration.assertions
      ++ lib.mapAttrsToList (option: _: {
        assertion = !cfg.publicApi.enable || cfg.credentials.${option} != null;
        message = "aos.sandbox.controllerService.credentials.${option} is required when publicApi.enable is true";
      })
      publicCredentialNames
      ++ [
        {
          assertion =
            (cfg.credentials.publicApiEntitlements == null)
            == (cfg.credentials.publicApiEntitlementPublicKey == null);
          message = "public API first-capability entitlements and their verifier must be provisioned together";
        }
      ];

    aos.users.users.aos-view-publisher = lib.mkIf cfg.publisherIngress.enable {
      uid = cfg.publisherIngress.uid;
      group = "aos-view-publisher";
      home = "/";
      shell = "/sbin/nologin";
      description = "AOS networkless project publisher registration process";
      extraGroups = [];
    };
    aos.users.groups.aos-view-publisher = lib.mkIf cfg.publisherIngress.enable {
      gid = cfg.publisherIngress.gid;
      members = [];
    };

    systemd.sockets.aos-sandboxd-publisher = lib.mkIf cfg.publisherIngress.enable {
      description = "AOS project publisher registration listener";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-publisher/control.sock";
        FileDescriptorName = "aos-sandboxd-publisher";
        Service = "aos-sandboxd.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-view-publisher";
        SocketMode = "0660";
        DirectoryMode = "0711";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandboxd = {
      description = "AOS unprivileged sandbox node controller";
      wantedBy = ["multi-user.target"];
      requires =
        [
          "aos-sandbox-hostd.service"
          "aos-storaged.service"
          "aos-sandbox-mountd.service"
          "aos-netd.service"
        ]
        ++ lib.optional ownershipAuthority.enable "aos-sandbox-ownershipd.socket"
        ++ lib.optional cfg.publisherIngress.enable "aos-sandboxd-publisher.socket";
      after =
        [
          "aos-sandbox-hostd.service"
          "aos-storaged.service"
          "aos-sandbox-mountd.service"
          "aos-netd.service"
          "local-fs.target"
        ]
        ++ lib.optional ownershipAuthority.enable "aos-sandbox-ownershipd.socket"
        ++ lib.optional cfg.publisherIngress.enable "aos-sandboxd-publisher.socket";
      unitConfig = {
        RequiresMountsFor = ["/sys/fs/cgroup"];
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        ExecStart =
          "${cfg.package}/bin/aos-sandboxd ${toString controller.uid} ${toString controller.gid}"
          + lib.optionalString cfg.publicApi.enable " --public-api"
          + lib.optionalString cfg.publisherIngress.enable " --publisher-ingress";
        Sockets = lib.optional cfg.publisherIngress.enable "aos-sandboxd-publisher.socket";
        ExecStartPre = brokerSessionConfiguration.installCommands;
        LoadCredential =
          nodeCredentials
          ++ cacheReplayCredentials
          ++ cacheReadbackCredentials
          ++ guestRootTemplateCredentials
          ++ brokerPlanCredentials
          ++ mountPlanCredentials
          ++ opensshAttachCredentials
          ++ ownershipCredentials
          ++ brokerSessionConfiguration.loadCredentials
          ++ publicCredentials
          ++ bootstrapCredentials
          ++ operatorRecoveryCredentials
          ++ publisherScopeCredential
          ++ publisherPolicySourceCredentials;
        Restart = "on-failure";
        RestartSec = "2s";
        TimeoutStartSec = "90s";
        User = "aos-sandboxd";
        Group = "aos-sandboxd";
        StateDirectory = [
          "aos/sandboxd"
          "aos/sandbox/source-domains"
          "aos/sandbox/cache-residency"
          "aos/sandbox/cache-residency/objects"
          "aos/sandboxd/cache-residency-authority"
          "aos/sandboxd/view-sources"
        ];
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandboxd";
        # Traversal grants no access to diagnostics or authority; the public
        # socket accepts only registered mutually authenticated TLS clients.
        RuntimeDirectoryMode =
          if cfg.publicApi.enable
          then "0755"
          else "0750";
        UMask = "0077";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitCORE = 0;
        LimitNOFILE = 128;
        LockPersonality = true;
        MemoryMax = "512M";
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        TasksMax = 8;
      };
    };

    systemd.services.aos-view-publisher = lib.mkIf cfg.publisherIngress.enable {
      description = "AOS networkless project publisher registration process";
      wantedBy = ["multi-user.target"];
      requires = ["aos-sandboxd.service" "aos-sandboxd-publisher.socket"];
      after = ["aos-sandboxd.service" "aos-sandboxd-publisher.socket"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-view-publisher";
        Restart = "on-failure";
        RestartSec = "2s";
        User = "aos-view-publisher";
        Group = "aos-view-publisher";
        UMask = "0077";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitCORE = 0;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        TasksMax = 4;
      };
    };
  };
}
