##! modules/sandbox/network-worker.nix — authenticated one-shot Network mutator
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.networkWorker;
  pinParent = "/sys/fs/bpf/aos/sandbox-network";
  mountBpffs = config.aos.config.artifacts.sandbox-network-mount-bpffs;
  preparePinRoot = config.aos.config.artifacts.sandbox-network-worker-ready;
  lifecycleAdmissionPrefix = lib.concatStringsSep " " [
    "${pkgs.aos-landlock}/bin/aos-landlock"
    "--require-abi 4"
    "--fs-read /proc/self/cgroup"
    "--fs-read /proc/self/fd"
    "--fs-read /proc/self/task"
    "--fs-read /sys/fs/cgroup"
    "--fs-ro /nix/store"
    "--"
  ];
in {
  options.aos.sandbox.networkWorker = {
    enable = lib.mkEnableOption "the authenticated one-shot Network preparation worker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-netd;
      defaultText = "pkgs.aos-netd";
      description = "Package containing the independently invoked Network worker.";
    };

    authorityDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/etc/aos/sandbox-network-authority";
      description = "Root-owned protected Network authority directory.";
    };
  };

  config = lib.mkIf cfg.enable {
    aos.config._artifactSources = {
      sandbox-network-mount-bpffs =
        if config.aos.config.frozenArtifacts ? "sandbox-network-mount-bpffs"
        then null
        else
          pkgs.writeShellScriptBin "aos-sandbox-network-mount-bpffs" ''
            set -eu

            validate_bpffs() {
              test "$(${pkgs.coreutils}/bin/stat --file-system --format=%t /sys/fs/bpf)" = cafe4a11
              # bpffs always adds the sticky bit to its configured root mode.
              test "$(${pkgs.coreutils}/bin/stat --format=%F:%u:%g:%a /sys/fs/bpf)" = directory:0:0:1700
              test "$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint /sys/fs/bpf --output FSTYPE)" = bpf

              mount_options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint /sys/fs/bpf --output VFS-OPTIONS)"
              for required_option in nosuid nodev noexec; do
                case ",$mount_options," in
                  *,$required_option,*) ;;
                  *) return 1 ;;
                esac
              done
            }

            filesystem="$(${pkgs.coreutils}/bin/stat --file-system --format=%t /sys/fs/bpf)"
            case "$filesystem" in
              cafe4a11)
                validate_bpffs
                ;;
              62656572)
                # Linux creates this kernel-owned empty sysfs mountpoint as 0555.
                test "$(${pkgs.coreutils}/bin/stat --format=%F:%u:%g:%a /sys/fs/bpf)" = directory:0:0:555
                ${pkgs.util-linux}/bin/mount \
                  --types bpf \
                  --options nosuid,nodev,noexec,mode=0700 \
                  bpf /sys/fs/bpf
                validate_bpffs
                ;;
              *)
                exit 1
                ;;
            esac

            # Validate each parent before creating its child. `mkdir -p` does
            # not repair substituted existing metadata, so a wrong parent is
            # rejected without adding anything beneath it.
            ${pkgs.coreutils}/bin/mkdir --parents --mode=0700 /sys/fs/bpf/aos
            test "$(${pkgs.coreutils}/bin/stat --format=%F:%u:%g:%a /sys/fs/bpf/aos)" = directory:0:0:700
            ${pkgs.coreutils}/bin/mkdir --parents --mode=0700 ${pinParent}
            test "$(${pkgs.coreutils}/bin/stat --format=%F:%u:%g:%a ${pinParent})" = directory:0:0:700
          '';

      sandbox-network-worker-ready =
        if config.aos.config.frozenArtifacts ? "sandbox-network-worker-ready"
        then null
        else
          pkgs.writeShellScriptBin "aos-sandbox-network-worker-ready" ''
            set -eu

            test "$(${pkgs.coreutils}/bin/stat --file-system --format=%t /sys/fs/bpf)" = cafe4a11
            # bpffs always adds the sticky bit to its configured root mode.
            test "$(${pkgs.coreutils}/bin/stat --format=%F:%u:%g:%a /sys/fs/bpf)" = directory:0:0:1700
            for directory in /sys/fs/bpf/aos ${pinParent}; do
              test "$(${pkgs.coreutils}/bin/stat --format=%F:%u:%g:%a "$directory")" = directory:0:0:700
            done
          '';
    };

    # systemd rejects .mount units below API filesystems such as /sys. This
    # narrowly scoped service deliberately avoids every mount-namespace-
    # inducing sandbox option so its fixed mount operation remains visible in
    # PID 1's namespace. All later services consume that one bpffs instance.
    systemd.services.aos-bpffs-mount = {
      description = "Mount the host-visible AOS BPF filesystem";
      wantedBy = ["local-fs.target"];
      before = [
        "local-fs.target"
        "aos-sandbox-network-worker-ready.service"
        "shutdown.target"
      ];
      conflicts = ["shutdown.target"];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${mountBpffs}/bin/aos-sandbox-network-mount-bpffs";
        # util-linux 2.42 otherwise selects fsopen(2), fsconfig(2),
        # fsmount(2), mount_setattr(2), and move_mount(2). This fixed mount
        # needs only the classic mount(2) operation.
        Environment = "LIBMOUNT_FORCE_MOUNT2=always";
        User = "root";
        Group = "root";
        UMask = "0077";
        CapabilityBoundingSet = ["CAP_SYS_ADMIN"];
        LimitNOFILE = 32;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        MemoryMax = "32M";
        NoNewPrivileges = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = ["native"];
        SystemCallFilter = ["@system-service" "mount" "~umount2"];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 8;
        TimeoutStartSec = "5s";
      };
    };

    systemd.sockets.aos-sandbox-network-worker = {
      description = "AOS authenticated one-transaction Network worker socket";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-network-worker-ready.service"];
      after = ["aos-sandbox-network-worker-ready.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-network-worker/control.sock";
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

    systemd.sockets.aos-sandbox-network-lifecycle-worker = {
      description = "AOS admission-only Network lifecycle worker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-network-lifecycle-worker/control.sock";
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

    systemd.sockets.aos-sandbox-network-observation-worker = {
      description = "AOS read-only Network postcondition worker socket";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-network-worker-ready.service"];
      after = ["aos-sandbox-network-worker-ready.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-network-observation-worker/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 1;
        SendBuffer = "1M";
        ReceiveBuffer = "1M";
      };
    };

    systemd.services.aos-sandbox-network-worker-ready = {
      description = "Prepare the protected sandbox Network bpffs root";
      requires = ["aos-bpffs-mount.service"];
      after = ["aos-bpffs-mount.service"];
      before = ["sysinit.target" "aos-sandbox-network-worker.socket" "shutdown.target"];
      conflicts = ["shutdown.target"];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${preparePinRoot}/bin/aos-sandbox-network-worker-ready";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitNOFILE = 64;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        MemoryMax = "64M";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = ["native"];
        SystemCallFilter = ["@system-service" "~mount" "~umount2"];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 8;
      };
    };

    # The default-on BPF-LSM loader retains its own private mount namespace.
    # When both features are enabled, make its preparation consume the host
    # bpffs established here instead of attempting a private fallback mount.
    systemd.services.aos-ebpf-lsm-policies = lib.mkIf config.aos.security.ebpfLsm.enable {
      requires = ["aos-bpffs-mount.service"];
      after = ["aos-bpffs-mount.service"];
    };

    # This distinct entrypoint proves only process, framing, and target-FD
    # admission. It deliberately receives no authority directory, replay state,
    # helper path, capability, or namespace-entry permission.
    systemd.services."aos-sandbox-network-lifecycle-worker@" = {
      description = "AOS admission-only Network lifecycle worker";
      unitConfig.RequiresMountsFor = ["/sys/fs/cgroup"];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${lifecycleAdmissionPrefix} ${cfg.package}/bin/aos-sandbox-network-lifecycle-worker";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        RuntimeMaxSec = "10s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        UMask = "0077";
        User = "root";
        Group = "root";
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        DevicePolicy = "closed";
        LimitNOFILE = 32;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryMax = "64M";
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
        # Direct masks provide readable deployment intent. The positive
        # Landlock is the alias-resistant boundary for ordinary files. Its
        # cross-domain ptrace rule separately denies another process's root,
        # fd, and namespace views. The focused worker qualification must prove
        # both properties on the deployed kernel.
        InaccessiblePaths = [
          "-${cfg.authorityDirectory}"
          "-/etc/credstore"
          "-/etc/credstore.encrypted"
          "-/run/credentials"
          "-/run/credstore"
          "-/run/credstore.encrypted"
          "-/run/systemd/credential.secret"
          "-/var/lib/aos/sandbox-network"
          "-/var/lib/aos-sandbox-network-worker"
        ];
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "landlock_add_rule"
          "landlock_create_ruleset"
          "landlock_restrict_self"
          "~bpf"
          "~mount"
          "~setns"
          "~umount2"
          "~unshare"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 8;
      };
    };

    systemd.services."aos-sandbox-network-observation-worker@" = {
      description = "AOS read-only Network postcondition worker";
      requires = ["aos-sandbox-network-worker-ready.service"];
      after = ["aos-sandbox-network-worker-ready.service"];
      unitConfig.RequiresMountsFor = ["/sys/fs/cgroup" "/sys/fs/bpf"];
      serviceConfig = {
        Type = "exec";
        ExecStart = ''
          ${cfg.package}/bin/aos-sandbox-network-observation-worker \
            ${pkgs.iproute2}/sbin/ip \
            ${pkgs.nftables}/bin/nft \
            ${cfg.package}/bin/aos-sandbox-network-worker \
            ${pkgs.aos-sandbox-network-observer}/bin/aos-sandbox-network-observer \
            ${pkgs.aos-sandbox-network-lease-gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o
        '';
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        RuntimeMaxSec = "15s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        UMask = "0077";
        User = "root";
        Group = "root";
        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
        ];
        AmbientCapabilities = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
        ];
        DevicePolicy = "closed";
        LimitNOFILE = 128;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryMax = "256M";
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
        ReadOnlyPaths = ["/nix/store" "/sys/fs/bpf"];
        InaccessiblePaths = [
          "-${cfg.authorityDirectory}"
          "-/etc/credstore"
          "-/etc/credstore.encrypted"
          "-/run/credentials"
          "-/run/credstore"
          "-/run/credstore.encrypted"
          "-/run/systemd/credential.secret"
          "-/var/lib/aos/sandbox-network"
          "-/var/lib/aos-sandbox-network-worker"
        ];
        RestrictAddressFamilies = ["AF_UNIX" "AF_NETLINK"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "bpf"
          "setns"
          "~@mount"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          "~umount2"
          "~unshare"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };

    systemd.services."aos-sandbox-network-worker@" = {
      description = "AOS authenticated Network preparation effect worker";
      requires = ["aos-sandbox-network-worker-ready.service"];
      after = ["aos-sandbox-network-worker-ready.service"];
      unitConfig.RequiresMountsFor = ["/sys/fs/cgroup" cfg.authorityDirectory];
      serviceConfig = {
        Type = "exec";
        ExecStart = ''
          ${cfg.package}/bin/aos-sandbox-network-worker \
            ${cfg.authorityDirectory} \
            /var/lib/aos-sandbox-network-worker \
            ${pkgs.iproute2}/sbin/ip \
            ${pkgs.nftables}/bin/nft \
            ${cfg.package}/bin/aos-sandbox-network-worker \
            ${pkgs.aos-sandbox-network-lease-gate-loader}/bin/aos-sandbox-network-lease-gate-loader \
            ${pkgs.aos-sandbox-network-lease-gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o
        '';
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        StateDirectory = "aos-sandbox-network-worker";
        StateDirectoryMode = "0700";
        RuntimeMaxSec = "20s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        UMask = "0077";
        User = "root";
        Group = "root";

        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
        ];
        AmbientCapabilities = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
        ];
        DevicePolicy = "closed";
        LimitNOFILE = 128;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryMax = "256M";
        MemoryDenyWriteExecute = false;
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
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        # ProtectKernelTunables also forces the entire bpffs API mount read-only.
        # Spell out systemd 261.2's complete tunables protection set, then use
        # its documented nested path exception for only this worker's pins.
        InaccessiblePaths = [
          "-/proc/kallsyms"
          "-/proc/kcore"
        ];
        ReadOnlyPaths = [
          cfg.authorityDirectory
          "-/proc/acpi"
          "-/proc/apm"
          "-/proc/asound"
          "-/proc/bus"
          "-/proc/fs"
          "-/proc/irq"
          "-/proc/latency_stats"
          "-/proc/mtrr"
          "-/proc/scsi"
          "-/proc/sys"
          "-/proc/sysrq-trigger"
          "-/proc/timer_stats"
          "/sys"
        ];
        ReadWritePaths = [pinParent];
        RestrictAddressFamilies = ["AF_UNIX" "AF_NETLINK"];
        RestrictNamespaces = ["net"];
        RestrictRealtime = true;
        RestrictSUIDSGID = false;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "bpf"
          "setns"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          "~mount"
          "~umount2"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };
  };
}
