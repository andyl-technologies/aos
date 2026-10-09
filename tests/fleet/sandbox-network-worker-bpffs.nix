# Proves the Network worker consumes the host-visible declarative bpffs mount.
{
  mkSystem,
  pkgs,
  ...
}: let
  probeSource = ../sandbox/network-worker-bpffs-probe.c;
  probe = pkgs.mkDerivation {
    pname = "aos-sandbox-network-worker-bpffs-probe";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [probeSource];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -I${pkgs.linux-headers}/include \
            ${probeSource} \
            -o "$out/bin/network-worker-bpffs-probe"
        '';
      }
    ];
    meta = {
      description = "Test-only Network worker bpffs mount-identity probe";
      license = "Apache-2.0";
    };
  };

  identityRecord = "/var/lib/aos-sandbox-network-worker/bpffs-identity";
  pin = "/sys/fs/bpf/aos/sandbox-network/vm-proof";
  socket = "/run/aos/sandbox-network-worker/control.sock";
  system = mkSystem [
    ../../systems/server-test.nix
    ({lib, ...}: {
      aos.sandbox.networkWorker = {
        enable = true;
        authorityDirectory = "/etc";
      };
      aos.image.budgets = {
        maxRootMiB = 704;
        maxDownloadMiB = 832;
      };
      environment.systemPackages = [probe pkgs.coreutils pkgs.systemd pkgs.util-linux];

      # Exercise the production template's namespace and filesystem hardening
      # while replacing only the protocol implementation with a focused pin
      # identity probe.
      systemd.services."aos-sandbox-network-worker@".serviceConfig.ExecStart = lib.mkForce ''
        ${probe}/bin/network-worker-bpffs-probe worker ${identityRecord} ${pin}
      '';
    })
  ];
in {
  name = "sandbox-network-worker-bpffs";
  timeout = 180;
  bootTimeout = 120;

  machines.vm = {inherit system;};

  testScript = ''
    import shlex

    BASH = "${pkgs.bash}/bin/bash"
    COREUTILS = "${pkgs.coreutils}/bin"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    PROBE = "${probe}/bin/network-worker-bpffs-probe"
    UNSHARE = "${pkgs.util-linux}/bin/unshare"

    def dump_bpffs_boot_diagnostics():
        units = (
            "aos-bpffs-mount.service aos-sandbox-network-worker-ready.service "
            "aos-sandbox-network-worker.socket"
        )
        print(vm.execute(f"systemctl status --no-pager -l {units}"))
        print(vm.execute(
            "systemctl show aos-bpffs-mount.service "
            "-p FragmentPath -p LoadState -p ActiveState -p SubState -p Result"
        ))
        print(vm.execute("systemctl cat aos-bpffs-mount.service"))
        print(vm.execute(
            "journalctl -b --no-pager -o short-monotonic "
            "-u aos-bpffs-mount.service "
            "-u aos-sandbox-network-worker-ready.service "
            "-u aos-sandbox-network-worker.socket"
        ))
        print(vm.execute("findmnt --target /sys/fs/bpf --output TARGET,SOURCE,FSTYPE,OPTIONS"))
        print(vm.execute("cat /proc/1/mountinfo"))

    def dump_worker_diagnostics():
        print(vm.execute(
            "systemctl status --no-pager -l "
            "'aos-sandbox-network-worker@*.service'"
        ))
        print(vm.execute(
            "journalctl -b --no-pager -o short-monotonic "
            "-u 'aos-sandbox-network-worker@*'"
        ))

    vm.wait_for_unit("multi-user.target", timeout=120)
    try:
        vm.wait_for_unit("aos-bpffs-mount.service", timeout=30)
        vm.wait_for_unit("aos-sandbox-network-worker-ready.service", timeout=30)
        vm.wait_for_unit("aos-sandbox-network-worker.socket", timeout=30)
    except Exception:
        dump_bpffs_boot_diagnostics()
        raise

    mount_unit = vm.succeed("systemctl cat aos-bpffs-mount.service")
    assert "Before=local-fs.target aos-sandbox-network-worker-ready.service shutdown.target" in mount_unit
    assert "Environment=LIBMOUNT_FORCE_MOUNT2=always" in mount_unit
    assert "SystemCallFilter=@system-service" in mount_unit
    assert "SystemCallFilter=mount" in mount_unit
    assert "SystemCallFilter=~umount2" in mount_unit
    for namespace_directive in (
        "BindPaths=",
        "BindReadOnlyPaths=",
        "InaccessiblePaths=",
        "MountAPIVFS=",
        "PrivateDevices=",
        "PrivateTmp=",
        "ProtectHome=",
        "ProtectSystem=",
        "ReadOnlyPaths=",
        "ReadWritePaths=",
        "RootDirectory=",
        "RootImage=",
    ):
        assert namespace_directive not in mount_unit
    assert vm.succeed(
        "systemctl show aos-bpffs-mount.service -p PrivateMounts --value"
    ).strip() == "no"
    vm.succeed("systemd-analyze verify aos-bpffs-mount.service")

    worker_unit = vm.succeed(
        "systemctl cat 'aos-sandbox-network-worker@.service'"
    )

    def directive_tokens(unit, directive):
        prefix = f"{directive}="
        return {
            token
            for line in unit.splitlines()
            if line.startswith(prefix)
            for token in shlex.split(line.removeprefix(prefix))
        }

    assert "ProtectKernelTunables=" not in worker_unit
    assert directive_tokens(worker_unit, "InaccessiblePaths") == {
        "-/proc/kallsyms",
        "-/proc/kcore",
    }
    assert directive_tokens(worker_unit, "ReadOnlyPaths") == {
        "/etc",
        "-/proc/acpi",
        "-/proc/apm",
        "-/proc/asound",
        "-/proc/bus",
        "-/proc/fs",
        "-/proc/irq",
        "-/proc/latency_stats",
        "-/proc/mtrr",
        "-/proc/scsi",
        "-/proc/sys",
        "-/proc/sysrq-trigger",
        "-/proc/timer_stats",
        "/sys",
    }
    assert directive_tokens(worker_unit, "ReadWritePaths") == {
        "/sys/fs/bpf/aos/sandbox-network",
    }

    assert vm.succeed(
        f"{COREUTILS}/stat --file-system --format=%t /sys/fs/bpf"
    ).strip() == "cafe4a11"
    assert vm.succeed(
        f"{COREUTILS}/stat --format=%F:%u:%g:%a /sys/fs/bpf"
    ).strip() == "directory:0:0:1700"
    for directory in ("/sys/fs/bpf/aos", "/sys/fs/bpf/aos/sandbox-network"):
        assert vm.succeed(
            f"{COREUTILS}/stat --format=%F:%u:%g:%a {directory}"
        ).strip() == "directory:0:0:700"

    # Run the exact readiness artifact in a throwaway mount namespace with a
    # non-bpffs bind mounted over its root. It must fail before changing the
    # host mount or creating protected children on the wrong filesystem.
    mount_bpffs = next(
        line.removeprefix("ExecStart=")
        for line in mount_unit.splitlines()
        if line.startswith("ExecStart=")
    )
    ready_unit = vm.succeed(
        "systemctl cat aos-sandbox-network-worker-ready.service"
    )
    ready = next(
        line.removeprefix("ExecStart=")
        for line in ready_unit.splitlines()
        if line.startswith("ExecStart=")
    )
    vm.succeed("mkdir -p /run/aos-wrong-bpffs")
    wrong_filesystem_check = """
      set -eu
      "$1" --bind /run/aos-wrong-bpffs /sys/fs/bpf
      if "$2" || "$3"; then
        exit 1
      fi
    """
    vm.succeed(
        f"{UNSHARE} --mount --propagation private {BASH} -c "
        f"{shlex.quote(wrong_filesystem_check)} ignored "
        f"{MOUNT} {mount_bpffs} {ready}"
    )
    vm.succeed("test ! -e /run/aos-wrong-bpffs/aos")
    assert vm.succeed(
        f"{COREUTILS}/stat --file-system --format=%t /sys/fs/bpf"
    ).strip() == "cafe4a11"

    # A valid private bpffs with a substituted first-level parent must fail
    # without creating the protected child beneath that wrong parent.
    wrong_parent_check = """
      set -eu
      "$1" --types bpf --options nosuid,nodev,noexec,mode=0700 bpf /sys/fs/bpf
      "$2" --mode=0755 /sys/fs/bpf/aos
      if "$3"; then
        exit 1
      fi
      test ! -e /sys/fs/bpf/aos/sandbox-network
    """
    vm.succeed(
        f"{UNSHARE} --mount --propagation private {BASH} -c "
        f"{shlex.quote(wrong_parent_check)} ignored "
        f"{MOUNT} {COREUTILS}/mkdir {mount_bpffs}"
    )

    # Exercise the helper's unmounted path under the production service's
    # capability and seccomp policy. util-linux is forced to use mount(2), so
    # no mount-FD-family syscall needs to be admitted.
    vm.succeed("systemctl stop aos-sandbox-network-worker.socket")
    vm.succeed("systemctl stop aos-sandbox-network-worker-ready.service")
    vm.succeed("systemctl stop aos-bpffs-mount.service")
    vm.succeed("umount /sys/fs/bpf")
    assert vm.succeed(
        f"{COREUTILS}/stat --file-system --format=%t /sys/fs/bpf"
    ).strip() == "62656572"
    underlying_bpffs_metadata = vm.succeed(
        f"{COREUTILS}/stat --format=%F:%u:%g:%a /sys/fs/bpf"
    ).strip()
    print(f"post-unmount /sys/fs/bpf metadata: {underlying_bpffs_metadata}")
    assert underlying_bpffs_metadata == "directory:0:0:555"
    try:
        vm.succeed("systemctl start aos-bpffs-mount.service")
    except Exception:
        dump_bpffs_boot_diagnostics()
        raise
    vm.succeed("systemctl start aos-sandbox-network-worker-ready.service")
    vm.succeed("systemctl start aos-sandbox-network-worker.socket")
    assert vm.succeed(
        f"{COREUTILS}/stat --file-system --format=%t /sys/fs/bpf"
    ).strip() == "cafe4a11"
    assert vm.succeed(
        f"{COREUTILS}/stat --format=%F:%u:%g:%a /sys/fs/bpf"
    ).strip() == "directory:0:0:1700"

    vm.succeed(f"test ! -e ${pin}")
    try:
        vm.succeed(f"{PROBE} connect ${socket}")
        vm.wait_until_succeeds(f"test -s ${identityRecord}", timeout=30)
    except Exception:
        dump_worker_diagnostics()
        raise
    vm.succeed(f"{PROBE} inspect ${pin}")

    worker_device, worker_inode, worker_mount_namespace, worker_magic = (
        vm.succeed(f"cat ${identityRecord}").split()
    )
    host_device, host_inode = vm.succeed(
        f"{COREUTILS}/stat --format='%d %i' /sys/fs/bpf/aos/sandbox-network"
    ).split()
    host_mount_namespace = vm.succeed(
        f"{COREUTILS}/stat --dereference --format=%i /proc/1/ns/mnt"
    ).strip()

    assert worker_magic == "cafe4a11"
    assert (worker_device, worker_inode) == (host_device, host_inode)
    assert worker_mount_namespace != host_mount_namespace
    vm.succeed("test ! -e /sys/fs/bpf/aos/outside-worker")
  '';
}
