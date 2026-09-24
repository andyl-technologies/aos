##! modules/sandbox/storage-worker.nix — cgroup-contained OpenZFS worker
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.storageWorker;

  landlockReadOnlyPrefix = lib.concatStringsSep " " [
    "${pkgs.aos-landlock}/bin/aos-landlock"
    "--require-abi 4"
    "--fs-read /"
    # Retain an explicit rule on the cgroup mount: after mount-namespace
    # entry, the rule anchored at `/` no longer covers this detached mount.
    "--fs-read /sys/fs/cgroup"
    "--fs-ro /nix/store"
    "--fs-rw /dev/zfs"
    "--"
  ];

  # The paired systemd and kernel policy preserves strict openat2 resolution
  # while rejecting setid creation through both direct and indirect modes.
  workerRestrictSuidSgid = true;

  # An inherited ring descriptor could bypass a syscall-only io_uring deny.
  # Worker startup also rejects such descriptors before protected opens.
  ioUringDeny = [
    "~io_uring_setup"
    "~io_uring_enter"
    "~io_uring_register"
  ];

  # The existing pin worker is not the future root-initializer domain. Keep
  # its ownership capability and root-mode mutation surface closed so source
  # wiring cannot be mistaken for deployable Create readiness.
  workspacePinWorkerCapabilities = [
    "CAP_SYS_ADMIN"
    "CAP_SYS_CHROOT"
  ];
  workspacePinWorkerRootMutationDeny = [
    "~chmod"
    "~fchmod"
    "~fchmodat"
    "~fchmodat2"
  ];
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

    authorityDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/etc/aos/sandbox-storage-authority";
      description = "Root-owned protected Storage authority directory opened independently by pin workers.";
    };

    workerUid = lib.mkOption {
      type = lib.types.int;
      default = 992;
      description = "Stable non-root UID of the serialized OpenZFS transaction worker.";
    };

    workerGid = lib.mkOption {
      type = lib.types.int;
      default = 992;
      description = "Stable non-root GID of the serialized OpenZFS transaction worker.";
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
      {
        assertion = cfg.workerUid > 0 && cfg.workerUid < 65536;
        message = "aos.sandbox.storageWorker.workerUid must be in 1..65535";
      }
      {
        assertion = cfg.workerGid > 0 && cfg.workerGid < 65536;
        message = "aos.sandbox.storageWorker.workerGid must be in 1..65535";
      }
      {
        assertion =
          !builtins.elem "CAP_CHOWN" workspacePinWorkerCapabilities
          && !builtins.elem "CAP_FOWNER" workspacePinWorkerCapabilities
          && builtins.elem "~fchmod" workspacePinWorkerRootMutationDeny;
        message = "the unqualified workspace pin worker must not gain root-initializer authority";
      }
    ];

    # The socket serializes this dedicated identity, while the broker proves
    # whole-cgroup quiescence before another transaction may be dispatched.
    aos.users.users.aos-sandbox-zfs-worker = {
      uid = cfg.workerUid;
      group = "aos-sandbox-zfs-worker";
      home = "/";
      shell = "/sbin/nologin";
      description = "AOS serialized OpenZFS transaction worker";
      extraGroups = [];
    };
    aos.users.groups.aos-sandbox-zfs-worker = {
      gid = cfg.workerGid;
      members = [];
    };

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
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 1;
      };
    };

    systemd.sockets.aos-sandbox-workspace-pin-worker = {
      description = "AOS authenticated workspace root-pin worker socket";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-workspace-pin-worker/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 1;
      };
    };

    systemd.sockets.aos-sandbox-workspace-pin-observer = {
      description = "AOS authenticated workspace root-pin observer socket";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-workspace-pin-observer/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 1;
      };
    };

    systemd.sockets.aos-sandbox-workspace-root-initializer = {
      description = "AOS authenticated workspace root initializer socket";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-workspace-root-initializer/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 1;
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
        ExecStart = "${landlockReadOnlyPrefix} ${cfg.package}/bin/aos-sandbox-zfs-worker ${cfg.zfsPackage}/sbin/zfs";
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
        User = "aos-sandbox-zfs-worker";
        Group = "aos-sandbox-zfs-worker";

        CapabilityBoundingSet = ["CAP_SYS_ADMIN"];
        AmbientCapabilities = ["CAP_SYS_ADMIN"];
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/zfs rw"];
        LimitNOFILE = 128;
        LimitCORE = 0;
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
        RestrictSUIDSGID = workerRestrictSuidSgid;
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
          "landlock_create_ruleset"
          "landlock_add_rule"
          "landlock_restrict_self"
          "~chmod"
          "~fchmod"
          "~fchmodat"
          "~fchmodat2"
        ] ++ ioUringDeny;
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };

    systemd.services."aos-sandbox-workspace-pin-worker@" = {
      description = "AOS authenticated workspace root-pin effect worker";
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      unitConfig.RequiresMountsFor = [
        "/sys/fs/cgroup"
        cfg.authorityDirectory
      ];
      serviceConfig = {
        Type = "exec";
        ExecStart = ''
          ${cfg.package}/bin/aos-sandbox-workspace-pin-worker \
            ${cfg.zfsPackage}/sbin/zfs \
            ${cfg.authorityDirectory} \
            /var/lib/aos-sandbox-workspace-pin-worker
        '';
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        StateDirectory = "aos-sandbox-workspace-pin-worker";
        StateDirectoryMode = "0700";
        RuntimeMaxSec = "32s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        UMask = "0077";
        User = "root";
        Group = "root";

        CapabilityBoundingSet = workspacePinWorkerCapabilities;
        AmbientCapabilities = workspacePinWorkerCapabilities;
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/zfs rw"];
        LimitNOFILE = 128;
        LimitCORE = 0;
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
        ReadOnlyPaths = [cfg.authorityDirectory];
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = ["mnt"];
        RestrictRealtime = true;
        RestrictSUIDSGID = workerRestrictSuidSgid;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "setns"
          "fsopen"
          "fsconfig"
          "fsmount"
          "move_mount"
          "mount_setattr"
          "umount2"
          "socket"
          "connect"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          # The worker connects only to the root-only initializer socket;
          # RestrictAddressFamilies limits the new client surface to AF_UNIX.
          "~socketpair"
        ] ++ workspacePinWorkerRootMutationDeny ++ ioUringDeny;
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };

    systemd.services."aos-sandbox-workspace-root-initializer@" = {
      description = "AOS detached workspace root initializer";
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      unitConfig.RequiresMountsFor = [
        "/sys/fs/cgroup"
        cfg.authorityDirectory
        "/var/lib/aos-sandbox-workspace-pin-worker"
      ];
      serviceConfig = {
        Type = "exec";
        ExecStart = ''
          ${cfg.package}/bin/aos-sandbox-workspace-root-initializer \
            ${cfg.zfsPackage}/sbin/zfs \
            ${cfg.authorityDirectory} \
            /var/lib/aos-sandbox-workspace-pin-worker
        '';
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
        User = "root";
        Group = "root";

        # Only this one-shot process can normalize a Create root. Pathname
        # ownership/mode mutation is excluded; the code uses exact root FDs.
        CapabilityBoundingSet = [
          "CAP_SYS_ADMIN"
          "CAP_SYS_CHROOT"
          "CAP_CHOWN"
          "CAP_FOWNER"
        ];
        AmbientCapabilities = [
          "CAP_SYS_ADMIN"
          "CAP_SYS_CHROOT"
          "CAP_CHOWN"
          "CAP_FOWNER"
        ];
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/zfs rw"];
        LimitNOFILE = 128;
        LimitCORE = 0;
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
        ReadOnlyPaths = [
          cfg.authorityDirectory
          "/var/lib/aos-sandbox-workspace-pin-worker"
        ];
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = ["mnt"];
        RestrictRealtime = true;
        RestrictSUIDSGID = workerRestrictSuidSgid;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "setns"
          "fsopen"
          "fsconfig"
          "fsmount"
          "mount_setattr"
          "fchown"
          "fchmod"
          "~chmod"
          "~chown"
          "~lchown"
          "~fchownat"
          "~fchmodat"
          "~fchmodat2"
          "~mount"
          "~move_mount"
          "~umount2"
          "~pivot_root"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          "~socket"
          "~socketpair"
          "~connect"
        ] ++ ioUringDeny;
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };

    systemd.services."aos-sandbox-workspace-pin-observer@" = {
      description = "AOS authenticated workspace root-pin observation helper";
      requires = ["aos-sandbox-zfs-ready.service"];
      after = ["aos-sandbox-zfs-ready.service"];
      unitConfig.RequiresMountsFor = [
        "/sys/fs/cgroup"
        cfg.authorityDirectory
      ];
      serviceConfig = {
        Type = "exec";
        ExecStart = ''
          ${landlockReadOnlyPrefix} \
            ${cfg.package}/bin/aos-sandbox-workspace-pin-observer \
            ${cfg.zfsPackage}/sbin/zfs \
            ${cfg.authorityDirectory}
        '';
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        RuntimeMaxSec = "37s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        UMask = "0077";
        User = "root";
        Group = "root";

        # CAP_SYS_CHROOT is required by setns(2) when joining a mount
        # namespace even though chroot(2) itself remains denied below.
        CapabilityBoundingSet = [
          "CAP_SYS_ADMIN"
          "CAP_SYS_CHROOT"
        ];
        AmbientCapabilities = [
          "CAP_SYS_ADMIN"
          "CAP_SYS_CHROOT"
        ];
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/zfs rw"];
        LimitNOFILE = 128;
        LimitCORE = 0;
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
        ReadOnlyPaths = [cfg.authorityDirectory];
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = ["mnt"];
        RestrictRealtime = true;
        RestrictSUIDSGID = workerRestrictSuidSgid;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "setns"
          "~mount"
          "~umount2"
          "~fsopen"
          "~fsconfig"
          "~fsmount"
          "~move_mount"
          "~mount_setattr"
          # The observer may clone one verified workspace mount into an
          # unattached descriptor; attachment and separate mutation syscalls
          # stay denied.
          "open_tree"
          # The LocalLive variant applies read-only attributes before the
          # cloned descriptor is published to the observer.
          "open_tree_attr"
          "~pivot_root"
          "~chroot"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          "~socket"
          "~socketpair"
          "~connect"
          "landlock_create_ruleset"
          "landlock_add_rule"
          "landlock_restrict_self"
          "~chmod"
          "~fchmod"
          "~fchmodat"
          "~fchmodat2"
        ] ++ ioUringDeny;
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };
  };
}
