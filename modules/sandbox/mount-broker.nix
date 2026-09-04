##! modules/sandbox/mount-broker.nix — descriptor-only root mount boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.mountBroker;
  controller = config.aos.sandbox.controller;
  hostBroker = config.aos.sandbox.hostBroker;
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

    credentials = lib.mapAttrs (name: credentialFile:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "External system credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
      })
    credentialFields;
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
          assertion =
            !hostBroker.enable
            || cfg.credentials.journalMacKey == null
            || hostBroker.credentials.journalMacKey == null
            || cfg.credentials.journalMacKey != hostBroker.credentials.journalMacKey;
          message = "host and mount brokers must use distinct journalMacKey credential sources";
        }
      ];

    systemd.sockets.aos-sandbox-mountd = {
      description = "AOS sandbox mount broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-mount/control.sock";
        FileDescriptorName = "aos-sandbox-mount";
        Service = "aos-sandbox-mountd.service";
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-mountd = {
      description = "AOS descriptor-only sandbox mount broker";
      requires = ["aos-sandbox-mountd.socket"];
      after = ["aos-sandbox-mountd.socket" "local-fs.target"];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/aos-sandbox-mountd ${toString controller.uid} ${toString controller.gid} ${cfg.package}/bin/aos-sandbox-mount-helper";
        LoadCredential = loadCredentials;
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
