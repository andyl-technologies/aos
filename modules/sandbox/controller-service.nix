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
in {
  options.aos.sandbox.controllerService = {
    enable = lib.mkEnableOption "the production unprivileged sandbox node controller";

    publicApi.enable = lib.mkEnableOption "the registered mutual-TLS controller API on /run/aos/sandboxd/public.sock";

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
            (cfg.credentials.opensshAttachGrantSigningKey == null
              && cfg.credentials.opensshAttachCaSigningKey == null
              && attachTrustCredential == null
              && attachGrantPublicKeyCredential == null)
            || (cfg.credentials.opensshAttachGrantSigningKey != null
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
      publicCredentialNames;

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
        ++ lib.optional ownershipAuthority.enable "aos-sandbox-ownershipd.socket";
      after =
        [
          "aos-sandbox-hostd.service"
          "aos-storaged.service"
          "aos-sandbox-mountd.service"
          "aos-netd.service"
          "local-fs.target"
        ]
        ++ lib.optional ownershipAuthority.enable "aos-sandbox-ownershipd.socket";
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
          + lib.optionalString cfg.publicApi.enable " --public-api";
        ExecStartPre = brokerSessionConfiguration.installCommands;
        LoadCredential =
          nodeCredentials
          ++ cacheReplayCredentials
          ++ guestRootTemplateCredentials
          ++ brokerPlanCredentials
          ++ mountPlanCredentials
          ++ opensshAttachCredentials
          ++ ownershipCredentials
          ++ brokerSessionConfiguration.loadCredentials
          ++ publicCredentials;
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
  };
}
