##! modules/sandbox/mount-broker.nix — descriptor-only root mount boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.mountBroker;
  hostBroker = config.aos.sandbox.hostBroker;
  sourceProvider = config.aos.sandbox.sourceProvider;
  signedCarrier = config.boot.initrd.systemd.mountExecutableCarrier;
  selectedStage0 = config.aos.boot.initrd.stage0;
  daemonPath =
    if cfg.useExecutableCarrier
    then "/run/aos/mount-executable-carrier/daemon"
    else "${cfg.package}/bin/aos-sandbox-mountd";
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  brokerSessionEndpoints = [
    {
      name = "mount-broker";
      description = "Mount broker";
      role = "broker";
      journalRoot = "/var/lib/aos/sandbox-mount/broker-session";
      options = {
        manifest = "brokerSessionManifest";
        hello = "brokerSessionHelloKey";
        record = "brokerSessionOutcomeKey";
      };
    }
    {
      name = "mount-host-client";
      description = "RootMount-to-Host client";
      role = "client";
      journalRoot = "/var/lib/aos/sandbox-mount/broker-session/host";
      options = {
        manifest = "brokerSessionHostManifest";
        hello = "brokerSessionHostHelloKey";
        record = "brokerSessionHostRecordKey";
      };
    }
  ];
  brokerSessionConfiguration = brokerSession.configure cfg.credentials brokerSessionEndpoints;
  credentialFields = {
    brokerPlanPolicy = "broker-plan-policy.cbor";
    brokerPlanPublicKey = "broker-plan-public-key";
    brokerRevocationScope = "broker-revocation-scope";
    ownershipLeasePolicy = "ownership-lease-policy.cbor";
    ownershipLeasePublicKey = "ownership-lease-public-key";
    nodeId = "node-id";
    journalMacKey = "journal-mac-key";
  };
  configuredCredentials =
    lib.filterAttrs (name: _: cfg.credentials.${name} != null) credentialFields;
  # Sources are names in the platform credential namespace, not paths or
  # values. PID 1 copies their runtime bytes into the service credential
  # directory, so evaluating and building the system never captures secrets in
  # a derivation or Nix store path.
  loadCredentials =
    lib.mapAttrsToList (
      name: _: "${credentialFields.${name}}:/run/credentials/@system/${cfg.credentials.${name}}"
    )
    configuredCredentials;
in {
  options.aos.sandbox.mountBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox mount broker";

    sourceProviderSession.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Connect to the separate SourceProvider service after installing a protected AOSMMSTA1 Mount startup policy and externally provisioning RootMount's authority at /var/lib/aos/sandbox-mount/source-provider-authority and Provider's authority at /var/lib/aos/source-provider/authority. This enables authenticated session, pending Acquire observation, and Reserved Inventory readback; source effects and SourceRoot handoff remain unavailable.";
    };

    useExecutableCarrier = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run Mount's daemon from the signed, verified first-launcher carrier mounted by SELinux stage0. Requires the selected initrd and stage0 to name the same carrier, with a daemon built from this module's package.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-mountd;
      defaultText = "pkgs.aos-sandbox-mountd";
      description = "The independently packaged mount broker and helper.";
    };

    maximumRetainedMounts = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0);
      default = 1024;
      description = "The hard admission ceiling for mount descriptors retained by PID 1 across broker restarts.";
    };

    credentials =
      lib.mapAttrs (name: credentialFile:
        lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External system credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
        })
      credentialFields
      // brokerSession.mkOptions brokerSessionEndpoints;
  };

  config = lib.mkIf cfg.enable {
    assertions =
      lib.mapAttrsToList (name: credentialFile: {
        assertion = cfg.credentials.${name} != null;
        message = "aos.sandbox.mountBroker.credentials.${name} is required for ${credentialFile}";
      })
      credentialFields
      ++ [
        {
          assertion = !cfg.sourceProviderSession.enable || sourceProvider.enable;
          message = "aos.sandbox.mountBroker.sourceProviderSession.enable requires aos.sandbox.sourceProvider.enable";
        }
        {
          assertion =
            !cfg.useExecutableCarrier
            || (signedCarrier
              != null
              && selectedStage0 != null
              && (selectedStage0.passthru.mountCarrierFirstLauncher or false)
              && selectedStage0.passthru ? mountExecutableCarrier
              && selectedStage0.passthru.mountExecutableCarrier != null
              && toString selectedStage0.passthru.mountExecutableCarrier == toString signedCarrier
              && signedCarrier.passthru ? daemon
              && toString signedCarrier.passthru.daemon == toString cfg.package);
          message = "aos.sandbox.mountBroker.useExecutableCarrier requires a matching signed first-launcher stage0 carrier whose daemon is mountBroker.package";
        }
        {
          assertion =
            !hostBroker.enable
            || cfg.credentials.journalMacKey == null
            || hostBroker.credentials.journalMacKey == null
            || cfg.credentials.journalMacKey != hostBroker.credentials.journalMacKey;
          message = "host and mount brokers must use distinct journalMacKey credential sources";
        }
      ]
      ++ brokerSessionConfiguration.assertions;

    systemd.sockets.aos-sandbox-mountd = {
      description = "AOS sandbox mount broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-mount/control.sock";
        FileDescriptorName = "aos-sandbox-mount";
        Service = "aos-sandbox-mountd.service";
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-mountd = {
      description = "AOS descriptor-only sandbox mount broker";
      requires = ["aos-sandbox-mountd.socket"] ++ lib.optional cfg.sourceProviderSession.enable "aos-source-providerd.socket";
      after = ["aos-sandbox-mountd.socket" "local-fs.target"] ++ lib.optional cfg.sourceProviderSession.enable "aos-source-providerd.socket";
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        NotifyAccess = "main";
        ExecStartPre =
          brokerSessionConfiguration.installCommands
          ++ lib.optionals cfg.sourceProviderSession.enable [
            "${daemonPath} --check-source-provider-authority"
          ];
        # The service does not provision RootMount custody; the daemon checks
        # its fixed files, peer and signed hello before retaining the session.
        ExecStart = "${daemonPath} ${cfg.package}/bin/aos-sandbox-mount-helper${lib.optionalString cfg.sourceProviderSession.enable " --source-provider"}";
        LoadCredential = loadCredentials ++ brokerSessionConfiguration.loadCredentials;
        Restart = "on-failure";
        RestartSec = "2s";
        FileDescriptorStoreMax = cfg.maximumRetainedMounts;
        FileDescriptorStorePreserve = "yes";
        StateDirectory = "aos/sandbox-mount";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-mount-catalog";
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "restart";
        UMask = "0077";

        CapabilityBoundingSet = ["CAP_SYS_ADMIN" "CAP_SYS_CHROOT"];
        AmbientCapabilities = ["CAP_SYS_ADMIN" "CAP_SYS_CHROOT"];
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/fuse rw"];
        LimitNOFILE = 4096;
        LockPersonality = true;
        MemoryHigh = "512M";
        MemoryMax = "1G";
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = false;
        PrivateTmp = true;
        ProcSubset = "all";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        TasksMax = 64;
      };
    };
  };
}
