##! modules/sandbox/host-broker.nix — fixed root runtime broker boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.hostBroker;
  controller = config.aos.sandbox.controller;
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
  };

  config = lib.mkIf cfg.enable {
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
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox-host";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-host";
        RuntimeDirectoryMode = "0710";
        UMask = "0077";

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
