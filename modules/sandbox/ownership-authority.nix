##! modules/sandbox/ownership-authority.nix — protected local ownership lease service
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.ownershipAuthority;
  controller = config.aos.sandbox.controller;
in {
  options.aos.sandbox.ownershipAuthority = {
    enable = lib.mkEnableOption "the fixed local sandbox ownership authority";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-ownershipd;
      defaultText = "pkgs.aos-sandbox-ownershipd";
      description = "The independently packaged protected ownership authority executable.";
    };

    credentials.sessionKey = lib.mkOption {
      type = lib.types.nullOr lib.serviceTypes.credentialName;
      default = null;
      description = "External 32-byte local ownership-session key shared with the controller; its bytes never enter the Nix store.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.credentials.sessionKey != null;
        message = "aos.sandbox.ownershipAuthority.credentials.sessionKey is required";
      }
    ];

    systemd.sockets.aos-sandbox-ownershipd = {
      description = "AOS controller-facing ownership authority socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-ownership/control.sock";
        FileDescriptorName = "aos-sandbox-ownership";
        Service = "aos-sandbox-ownershipd.service";
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-ownershipd = {
      description = "AOS fixed protected ownership authority";
      requires = ["aos-sandbox-ownershipd.socket"];
      after = ["aos-sandbox-ownershipd.socket" "local-fs.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-sandbox-ownershipd ${toString controller.uid} ${toString controller.gid}";
        LoadCredential = [
          "ownership-session-key:/run/credentials/@system/${cfg.credentials.sessionKey}"
        ];
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox/multi-node";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-ownership";
        RuntimeDirectoryMode = "0710";
        UMask = "0077";

        # The fixed bootstrap, issuer inbox, and journal remain root-owned;
        # systemd credentials contain only the local record MAC key.
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
