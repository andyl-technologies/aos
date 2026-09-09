##! modules/sandbox/storage-broker.nix — authenticated root Storage repair boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.storageBroker;
  controller = config.aos.sandbox.controller;
  worker = config.aos.sandbox.storageWorker;
  minimumIdentityRange = 65536;
in {
  options.aos.sandbox.storageBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox Storage repair broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-storaged;
      defaultText = "pkgs.aos-storaged";
      description = "The independently packaged Storage repair and inventory broker.";
    };

    zfsPackage = lib.mkOption {
      type = lib.types.package;
      default = worker.zfsPackage;
      defaultText = "config.aos.sandbox.storageWorker.zfsPackage";
      description = "The exact AOS OpenZFS package compiled into broker worker requests.";
    };

    authorityDirectory = lib.mkOption {
      type = lib.types.str;
      default = worker.authorityDirectory;
      defaultText = "config.aos.sandbox.storageWorker.authorityDirectory";
      description = "Existing root-owned Storage authority shared with the authenticated pin workers.";
    };

    bootstrapDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/etc/aos/sandbox-storage-bootstrap";
      description = "Existing root-owned directory containing storage-genesis.catalog and storage-minimum-generation.";
    };

    identityPoolStart = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value >= minimumIdentityRange);
      default = 65536;
      description = "First host identity in the finite workspace subordinate-identity pool.";
    };

    identityPoolSize = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value >= minimumIdentityRange);
      default = 268435456;
      description = "Number of host identities in the finite workspace subordinate-identity pool.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = worker.enable;
        message = "aos.sandbox.storageBroker requires aos.sandbox.storageWorker";
      }
      {
        assertion = toString cfg.zfsPackage == toString worker.zfsPackage;
        message = "aos.sandbox.storageBroker and storageWorker must use the same OpenZFS package";
      }
      {
        assertion = lib.hasPrefix "/" cfg.authorityDirectory;
        message = "aos.sandbox.storageBroker.authorityDirectory must be absolute";
      }
      {
        assertion = lib.hasPrefix "/" cfg.bootstrapDirectory;
        message = "aos.sandbox.storageBroker.bootstrapDirectory must be absolute";
      }
      {
        assertion = cfg.identityPoolStart + cfg.identityPoolSize <= 4294967295;
        message = "aos.sandbox.storageBroker identity pool must fit within u32";
      }
    ];

    # The controller receives traverse-only access to the socket directory. It
    # cannot unlink or replace the root-owned endpoint path.
    environment.etc."tmpfiles.d/aos-sandbox-storage.conf".text = ''
      d /run/aos/sandbox-storage 0710 root aos-sandboxd - -
    '';

    systemd.sockets.aos-storaged = {
      description = "AOS sandbox Storage broker socket";
      wantedBy = ["sockets.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-storage/control.sock";
        FileDescriptorName = "aos-storaged";
        Service = "aos-storaged.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        SendBuffer = "4M";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-storaged = {
      description = "AOS authenticated Storage repair and inventory broker";
      requires = [
        "aos-storaged.socket"
        "aos-sandbox-zfs-worker.socket"
        "aos-sandbox-workspace-pin-worker.socket"
        "aos-sandbox-workspace-pin-observer.socket"
      ];
      after = [
        "aos-storaged.socket"
        "aos-sandbox-zfs-ready.service"
        "local-fs.target"
      ];
      unitConfig = {
        RequiresMountsFor = [
          "/sys/fs/cgroup"
          cfg.authorityDirectory
          cfg.bootstrapDirectory
        ];
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${cfg.package}/bin/aos-storaged \
            ${toString controller.uid} \
            ${toString controller.gid} \
            ${toString cfg.identityPoolStart} \
            ${toString cfg.identityPoolSize} \
            ${cfg.zfsPackage}/sbin/zfs \
            ${cfg.authorityDirectory} \
            ${cfg.bootstrapDirectory}
        '';
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox-storage";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-pins/workspaces";
        RuntimeDirectoryMode = "0700";
        # Pins outlive broker executions; only typed retirement removes them.
        # The volatile root is discarded independently when the host reboots.
        RuntimeDirectoryPreserve = "yes";
        UMask = "0077";
        User = "root";
        Group = "root";

        # The long-running broker only authenticates state and dispatches
        # fixed one-shot workers. It receives no ZFS or mount capability.
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitNOFILE = 256;
        LimitCORE = 0;
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
        ReadOnlyPaths = [cfg.authorityDirectory cfg.bootstrapDirectory];
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
