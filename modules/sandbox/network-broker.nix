##! modules/sandbox/network-broker.nix — authenticated root Network inventory boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.networkBroker;
  controller = config.aos.sandbox.controller;
in {
  options.aos.sandbox.networkBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox Network broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-netd;
      defaultText = "pkgs.aos-netd";
      description = "The independently packaged Network inventory broker.";
    };

    maximumRetainedNamespaces = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 1024);
      # Keep the boundary active in the evaluated value as well as its option metadata.
      apply = value:
        if builtins.isInt value && value > 0 && value <= 1024
        then value
        else throw "aos.sandbox.networkBroker.maximumRetainedNamespaces must be an integer from 1 through 1024";
      default = 1024;
      description = "The simultaneous Network namespace custody ceiling; 1024 keeps systemd's LISTEN_FDNAMES environment string below Linux's per-string exec limit.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.services.dbus.enable;
        message = "aos.sandbox.networkBroker requires aos.services.dbus for bounded systemd FD-store readback";
      }
    ];

    systemd.sockets.aos-netd = {
      description = "AOS sandbox Network broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-network/control.sock";
        FileDescriptorName = "aos-netd";
        Service = "aos-netd.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        # The complete 16,384-row inventory is larger than the kernel's
        # ordinary Unix-socket default. Accepted sockets inherit this bound.
        SendBuffer = "4M";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-netd = {
      description = "AOS authenticated sandbox Network inventory broker";
      requires = ["aos-netd.socket" "dbus.socket"];
      after = ["aos-netd.socket" "dbus.socket" "local-fs.target"];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/aos-netd ${toString controller.uid} ${toString controller.gid}";
        Restart = "on-failure";
        RestartSec = "2s";
        FileDescriptorStoreMax = cfg.maximumRetainedNamespaces;
        FileDescriptorStorePreserve = "yes";
        StateDirectory = "aos/sandbox-network";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-pins/netns";
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "restart";
        UMask = "0077";

        # This first deployed surface is inventory-only. Network mutation and
        # its capabilities remain absent until the fixed helper and P0-06 gate
        # are complete.
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitNOFILE = cfg.maximumRetainedNamespaces + 128;
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
        TasksMax = 32;
      };
    };
  };
}
