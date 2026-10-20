##! modules/sandbox/ownership-authority.nix — protected local ownership lease service
{
  config,
  lib,
  pkgs,
  ...
}: let
  credentialNameType = import ./_credential-name-type.nix {inherit lib;};

  cfg = config.aos.sandbox.ownershipAuthority;
  controller = config.aos.sandbox.controller;
  protectedOrigin = config.aos.sandbox.resourceBank.parentEnclosure != null;
  service = config.systemd.services.aos-sandbox-ownershipd.serviceConfig;
  socket = config.systemd.sockets.aos-sandbox-ownershipd.socketConfig;
  controllerService = config.aos.sandbox.controllerService;
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
      type = lib.types.nullOr credentialNameType;
      default = null;
      description = "External 32-byte local ownership-session key shared with the controller; its bytes never enter the Nix store.";
    };
    credentials.signingKey = lib.mkOption {
      type = lib.types.nullOr credentialNameType;
      default = null;
      description = "External 32-byte local ownership signing seed matching the fixed protected bootstrap; never included in the Nix store.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          protectedOrigin
          && config.aos.sandbox.resourceBank.parentEnclosure.ownershipReceiving != null
          && config.aos.sandbox.resourceBank.parentEnclosure.ownershipSender != null;
        message = "the ownership daemon requires its genuine PID1 parent and distinct explicit Ownership receiving/sender subdivisions";
      }
      {
        assertion = cfg.credentials.sessionKey != null;
        message = "aos.sandbox.ownershipAuthority.credentials.sessionKey is required";
      }
      {
        assertion = controllerService.credentials.nodeId != null;
        message = "local ownership requires the same protected Controller node identity";
      }
      {
        assertion = cfg.credentials.signingKey != null;
        message = "aos.sandbox.ownershipAuthority.credentials.signingKey is required for fresh local issuance";
      }
      {
        assertion = (
          (socket.PassSubjectBeforeListen or false)
          && (socket.PassCredentials or false)
          && (socket.PassPIDFD or false)
          && !(socket.PassSecurity or false)
          && (service.StandardInput or null) == "null"
          && (service.StateDirectory or null) == "aos/sandbox/multi-node"
          && (service.StateDirectoryMode or null) == "0700"
          && (service.RuntimeDirectory or null) == "aos/sandbox-ownership"
          && (service.RuntimeDirectoryMode or null) == "0711"
        );
        message = "protected Ownership requires its actual fixed directory roster, named activation and credentials/pidfd before listen, without SCM_SECURITY";
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
        # The existing Ownership record grammar forbids SCM_SECURITY. Both
        # required identity options are installed by PID1 before bind instead.
        PassSubjectBeforeListen = true;
        PassSecurity = false;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        # The controller traverses this root-owned directory, but the socket
        # itself remains accessible only to its configured service UID.
        DirectoryMode = "0711";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-ownershipd = {
      description = "AOS fixed protected ownership authority";
      requires = ["aos-sandbox-ownershipd.socket"];
      after = ["aos-sandbox-ownershipd.socket" "local-fs.target"];
      serviceConfig = {
        Type = "simple";
        StandardInput = "null";
        ExecStart = "${cfg.package}/bin/aos-sandbox-ownershipd ${toString controller.uid} ${toString controller.gid}";
        LoadCredential = [
          "ownership-session-key:/run/credentials/@system/${cfg.credentials.sessionKey}"
          "ownership-signing-key:/run/credentials/@system/${cfg.credentials.signingKey}"
          "node-id:/run/credentials/@system/${controllerService.credentials.nodeId}"
        ];
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox/multi-node";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-ownership";
        RuntimeDirectoryMode = "0711";
        UMask = "0077";

        # The bootstrap/public key and journal remain root-owned. The signing
        # seed and session MAC key are separate external systemd credentials.
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
