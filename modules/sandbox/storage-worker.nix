##! modules/sandbox/storage-worker.nix — cgroup-contained OpenZFS worker
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.storageWorker;
in {
  options.aos.sandbox.storageWorker = {
    enable = lib.mkEnableOption "the fixed one-transaction OpenZFS worker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-zfs-worker;
      defaultText = "pkgs.aos-sandbox-zfs-worker";
      description = "The independently packaged typed OpenZFS worker.";
    };

    zfsPackage = lib.mkOption {
      type = lib.types.package;
      default = config.aos.sandbox.storageWorker.zfsModulePackage;
      defaultText = "config.aos.sandbox.storageWorker.zfsModulePackage";
      description = "The exact AOS-built OpenZFS executable package.";
    };

    zfsModulePackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.zfsForKernel config.system.build.kernel;
      defaultText = "pkgs.zfsForKernel config.system.build.kernel";
      description = "The exact-kernel OpenZFS module and matching userland package.";
    };

    allowTestExecutableOverride = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Allow a test-only executable package distinct from the module package.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          cfg.allowTestExecutableOverride
          || toString cfg.zfsPackage == toString cfg.zfsModulePackage;
        message = "aos.sandbox.storageWorker requires matching OpenZFS module and executable packages";
      }
    ];

    aos.kernel.modulePackages = [cfg.zfsModulePackage];
    aos.kernel.modules = ["zfs"];

    systemd.sockets.aos-sandbox-zfs-worker = {
      description = "AOS one-transaction OpenZFS worker socket";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-zfs-worker/control.sock";
        Accept = true;
        Service = "aos-sandbox-zfs-worker@.service";
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 64;
      };
    };

    systemd.services.aos-sandbox-zfs-ready = {
      description = "Load the fixed OpenZFS module and admit its control device";
      # A socket gets an implicit Before=sockets.target ordering, while a
      # normal service starts after basic.target.  Because the socket requires
      # this service, those defaults would form a boot transaction cycle.
      # Keep readiness in sysinit alongside udev instead.
      requires = [
        "systemd-udevd.service"
        "systemd-udev-trigger.service"
      ];
      after = [
        "systemd-udevd.service"
        "systemd-udev-trigger.service"
      ];
      before = [
        "sysinit.target"
        "aos-sandbox-zfs-worker.socket"
        "shutdown.target"
      ];
      conflicts = ["shutdown.target"];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        TimeoutStartSec = "8s";

        CapabilityBoundingSet = ["CAP_SYS_MODULE"];
        DevicePolicy = "closed";
        LimitNOFILE = 64;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        MemoryMax = "128M";
        NoNewPrivileges = true;
        PrivateDevices = false;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = ["native"];
        SystemCallFilter = ["@system-service" "finit_module" "init_module"];
        TasksMax = 16;
      };
      script = ''
        set -eu
        ${pkgs.kmod}/sbin/modprobe zfs

        attempts=0
        while :; do
          identity=$(${pkgs.coreutils}/bin/stat -c '%u:%g:%a' /dev/zfs 2>/dev/null || true)
          if [ -c /dev/zfs ] && [ "$identity" = "0:0:666" ]; then
            echo "OpenZFS control device ready: $identity"
            exit 0
          fi

          attempts=$((attempts + 1))
          if [ "$attempts" -ge 100 ]; then
            echo "OpenZFS control device did not become root:root 0666: $identity" >&2
            exit 1
          fi
          ${pkgs.coreutils}/bin/sleep 0.05
        done
      '';
    };

    systemd.services."aos-sandbox-zfs-worker@" = {
      description = "AOS cgroup-contained OpenZFS transaction worker";
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      unitConfig = {
        RequiresMountsFor = ["/sys/fs/cgroup"];
      };
      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/aos-sandbox-zfs-worker ${cfg.zfsPackage}/sbin/zfs";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        RuntimeMaxSec = "32s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        UMask = "0077";
        DynamicUser = true;

        CapabilityBoundingSet = ["CAP_SYS_ADMIN"];
        AmbientCapabilities = ["CAP_SYS_ADMIN"];
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/zfs rw"];
        LimitNOFILE = 128;
        LockPersonality = true;
        MemoryMax = "128M";
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = false;
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
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "~@mount"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          "~socket"
          "~socketpair"
          "~connect"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };
  };
}
