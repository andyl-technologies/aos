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
  brokerPlanCredentials =
    lib.optional (cfg.credentials.brokerPlanSigningKey != null)
    "broker-plan-signing-key:/run/credentials/@system/${cfg.credentials.brokerPlanSigningKey}";
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

    publicApi.enable = lib.mkEnableOption "registered mutual-TLS discovery on /run/aos/sandboxd/public.sock (mutation RPCs remain unavailable)";

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
          description = "Optional external 32-byte controller broker-plan signing seed for prepared authority publications.";
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
      requires = [
        "aos-sandbox-hostd.service"
        "aos-storaged.service"
        "aos-sandbox-mountd.service"
        "aos-netd.service"
      ];
      after = [
        "aos-sandbox-hostd.service"
        "aos-storaged.service"
        "aos-sandbox-mountd.service"
        "aos-netd.service"
        "local-fs.target"
      ];
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
        LoadCredential = nodeCredentials ++ brokerPlanCredentials ++ brokerSessionConfiguration.loadCredentials ++ publicCredentials;
        Restart = "on-failure";
        RestartSec = "2s";
        TimeoutStartSec = "90s";
        User = "aos-sandboxd";
        Group = "aos-sandboxd";
        StateDirectory = [
          "aos/sandboxd"
          "aos/sandbox/source-domains"
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
