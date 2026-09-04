##! modules/sandbox/host-broker.nix — fixed root runtime broker boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.hostBroker;
  controller = config.aos.sandbox.controller;
  authorityCredentialFields = {
    brokerPlanPolicy = "broker-plan-policy.cbor";
    brokerPlanPublicKey = "broker-plan-public-key";
    brokerRevocationScope = "broker-revocation-scope";
    ownershipLeasePolicy = "ownership-lease-policy.cbor";
    ownershipLeasePublicKey = "ownership-lease-public-key";
    nodeId = "node-id";
    journalMacKey = "journal-mac-key";
  };
  credentialFields =
    authorityCredentialFields
    // {backendReadiness = "backend-readiness.json";};
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
  options.aos.sandbox.hostBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox host broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-hostd;
      defaultText = "pkgs.aos-sandbox-hostd";
      description = "The independently packaged host broker executable.";
    };

    controllerUid = lib.mkOption {
      type = lib.types.int;
      default = 811;
      description = "Compatibility default for aos.sandbox.controller.uid.";
    };

    controllerGid = lib.mkOption {
      type = lib.types.int;
      default = 811;
      description = "Compatibility default for aos.sandbox.controller.gid.";
    };

    credentials = lib.mapAttrs (name: credentialFile:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description =
          if name == "backendReadiness"
          then "Optional protected boot-local readiness claims published externally as ${credentialFile}; ingestion alone never enables Apply."
          else "External system credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
      })
    credentialFields;
  };

  config = lib.mkIf cfg.enable {
    assertions =
      lib.mapAttrsToList (name: credentialFile: {
        assertion = cfg.credentials.${name} != null;
        message = "aos.sandbox.hostBroker.credentials.${name} is required for ${credentialFile}";
      })
      authorityCredentialFields;

    systemd.sockets.aos-sandbox-hostd = {
      description = "AOS sandbox host broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-host/control.sock";
        FileDescriptorName = "aos-sandbox-host";
        Service = "aos-sandbox-hostd.service";
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-hostd = {
      description = "AOS fixed-function sandbox host broker";
      requires = ["aos-sandbox-hostd.socket" "dbus.socket"];
      after = ["aos-sandbox-hostd.socket" "dbus.socket" "local-fs.target"];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-sandbox-hostd ${toString controller.uid} ${toString controller.gid} ${pkgs.systemd}/bin/systemd-nspawn";
        LoadCredential = loadCredentials;
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox-host";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-host";
        RuntimeDirectoryMode = "0710";
        UMask = "0077";

        # Do not grant CAP_SYS_PTRACE merely to make pidfd namespace ioctls
        # succeed. Launch stays gated until the worker proves the exact narrow
        # access needed for its pinned nspawn supervisor under this empty set.
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
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
      };
    };
  };
}
