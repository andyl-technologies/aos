# End-to-end proof for the fixed systemd-activated OpenZFS worker boundary.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  selectedTest = "process::tests::systemd_worker_vm_client";
  faultStateDirectory = "/run/aos-zfs-worker-test";
  descendantPidFile = "${faultStateDirectory}/descendant.pid";

  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-zfs-worker-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos-sandbox-zfs-worker.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    postBuild = ''
      mkdir worker-fixture
      count=0
      for candidate in target/debug/deps/aos_sandbox_storage-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" worker-fixture/aos-sandbox-zfs-worker-tests
          count=$((count + 1))
        fi
      done
      test "$count" -eq 1
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 worker-fixture/aos-sandbox-zfs-worker-tests "$out/bin/"
    '';
  };

  # This fault-only executable verifies the closed argv and empty environment.
  # The timeout case deliberately leaves the child's process group.
  fakeZfs = pkgs.mkDerivation {
    pname = "aos-sandbox-zfs-worker-fake-zfs";
    version = "0.1.0";
    src = null;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/sbin"
          $CC -std=c11 -Wall -Wextra -Werror -O2 \
            ${../sandbox/zfs-worker-fake.c} -o "$out/sbin/zfs"
        '';
      }
    ];
  };

  clientRunner = zfsPackage:
    pkgs.writeShellScriptBin "aos-sandbox-zfs-worker-client" ''
      set -eu
      read -r worker_case < /run/aos/zfs-worker-case
      exec ${pkgs.coreutils}/bin/env \
        AOS_ZFS_EXECUTABLE=${zfsPackage}/sbin/zfs \
        AOS_ZFS_WORKER_CASE="$worker_case" \
        ${fixture}/bin/aos-sandbox-zfs-worker-tests \
        --ignored --exact '${selectedTest}' --test-threads=1 --nocapture
    '';

  makeSystem = faultInjection:
    mkSystem [
      ../../systems/server-test.nix
      ({config, ...}: let
        zfs = pkgs.zfsForKernel config.system.build.kernel;
        selectedZfs =
          if faultInjection
          then fakeZfs
          else zfs;
        runner = clientRunner selectedZfs;
      in {
        aos.sandbox.storageWorker =
          {enable = true;}
          // lib.optionalAttrs faultInjection {
            zfsPackage = selectedZfs;
            allowTestExecutableOverride = true;
          };
        aos.image.budgets = {
          maxRootMiB = 1024;
          maxDownloadMiB = 1152;
        };
        environment.systemPackages = [pkgs.coreutils pkgs.systemd zfs];

        systemd.services."aos-sandbox-zfs-worker@".serviceConfig = lib.mkIf faultInjection {
          # Shorten only the independent PID 1 deadline for fault injection.
          RuntimeDirectory = "aos-zfs-worker-test";
          RuntimeDirectoryMode = "0700";
          RuntimeMaxSec = lib.mkForce "4s";
          ReadWritePaths = [faultStateDirectory];
        };

        systemd.services.aos-storaged = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${runner}/bin/aos-sandbox-zfs-worker-client";
            Slice = "aos-control.slice";
            TimeoutStartSec =
              if faultInjection
              then "15s"
              else "30s";
          };
        };
      })
    ];
in {
  name = "sandbox-zfs-worker";
  timeout = 480;
  bootTimeout = 180;

  machines = {
    real = {system = makeSystem false;};
    fault = {system = makeSystem true;};
  };

  testScript = ''
    COREUTILS = "${pkgs.coreutils}/bin"
    SOCKET = "/run/aos/sandbox-zfs-worker/control.sock"

    ZFS = "${pkgs.zfsForKernel (makeSystem false).config.system.build.kernel}/sbin/zfs"
    ZPOOL = "${pkgs.zfsForKernel (makeSystem false).config.system.build.kernel}/sbin/zpool"
    def worker_units(machine):
        output = machine.succeed(
            "systemctl list-units --all 'aos-sandbox-zfs-worker@*.service' "
            "--no-legend --plain"
        )
        return [line.split()[0] for line in output.splitlines() if line.strip()]

    def active_worker(machine):
        units = worker_units(machine)
        active = [
            unit for unit in units
            if machine.succeed(
                f"systemctl show '{unit}' -p ActiveState --value"
            ).strip() in ("activating", "active", "deactivating")
        ]
        assert len(active) == 1, (units, active)
        unit = active[0]
        cgroup = machine.succeed(
            f"systemctl show '{unit}' -p ControlGroup --value"
        ).strip()
        assert cgroup.startswith("/aos-control.slice/aos-sandbox-zfs-worker@"), cgroup
        return unit, cgroup

    def wait_worker_drained(machine, unit, cgroup):
        machine.wait_until_succeeds(
            f"state=$(systemctl show '{unit}' -p ActiveState --value 2>/dev/null || true); "
            "test \"$state\" = inactive -o \"$state\" = failed -o -z \"$state\"",
            timeout=15,
        )
        machine.wait_until_succeeds(
            f"test ! -e '/sys/fs/cgroup{cgroup}/cgroup.events' || "
            f"grep -qx 'populated 0' '/sys/fs/cgroup{cgroup}/cgroup.events'",
            timeout=15,
        )

    def assert_no_live_workers(machine):
        for unit in worker_units(machine):
            state = machine.succeed(
                f"systemctl show '{unit}' -p ActiveState --value"
            ).strip()
            assert state in ("inactive", "failed"), (unit, state)

    def wait_no_live_workers(machine):
        machine.wait_until_succeeds(
            "for unit in $(systemctl list-units --all "
            "'aos-sandbox-zfs-worker@*.service' --no-legend --plain "
            "| cut -d' ' -f1); do "
            "state=$(systemctl show \"$unit\" -p ActiveState --value); "
            "test \"$state\" = inactive -o \"$state\" = failed || exit 1; "
            "done",
            timeout=15,
        )
        assert_no_live_workers(machine)

    def run_real(case):
        real.succeed(f"printf '%s\\n' '{case}' > /run/aos/zfs-worker-case")
        real.succeed("systemctl start aos-storaged.service", timeout=30)
        wait_no_live_workers(real)

    def guid(name):
        return int(real.succeed(f"{ZFS} get -Hp -o value guid '{name}'").strip())

    for machine_name, machine in (("real", real), ("fault", fault)):
        machine.wait_for_unit("multi-user.target", timeout=120)
        machine.wait_for_unit("aos-sandbox-zfs-ready.service", timeout=20)
        machine.succeed("systemctl is-active --quiet aos-sandbox-zfs-ready.service")
        ready_properties = machine.succeed(
            "systemctl show aos-sandbox-zfs-ready.service "
            "-p MemoryPeak -p TasksCurrent -p TasksMax"
        )
        ready_values = dict(
            line.split("=", 1) for line in ready_properties.splitlines()
        )
        print(f"{machine_name} readiness usage: {ready_values}")
        assert int(ready_values["MemoryPeak"]) <= 128 * 1024 * 1024, ready_values
        assert ready_values["TasksCurrent"] == "0", ready_values
        assert ready_values["TasksMax"] == "16", ready_values
        assert machine.succeed(
            f"{COREUTILS}/stat -c '%u:%g:%a' /dev/zfs"
        ).strip() == "0:0:666"
        machine.succeed("test -d /sys/module/zfs")
        machine.wait_until_succeeds(f"test -S {SOCKET}", timeout=20)

    # A bad device identity disables only this optional storage endpoint.  It
    # must neither expose the socket nor turn an otherwise healthy host boot
    # into a failure.
    fault.succeed(
        "systemctl stop aos-sandbox-zfs-worker.socket "
        "aos-sandbox-zfs-ready.service"
    )
    fault.succeed(f"{COREUTILS}/chmod 0600 /dev/zfs")
    fault.fail("systemctl start aos-sandbox-zfs-worker.socket", timeout=15)
    fault.wait_until_fails(
        "systemctl is-active --quiet aos-sandbox-zfs-worker.socket", timeout=5
    )
    fault.fail(f"test -S {SOCKET}")
    fault.succeed("systemctl is-active --quiet multi-user.target")
    fault.succeed(f"{COREUTILS}/chmod 0666 /dev/zfs")
    fault.succeed(
        "systemctl reset-failed aos-sandbox-zfs-ready.service "
        "aos-sandbox-zfs-worker.socket"
    )
    fault.succeed("systemctl start aos-sandbox-zfs-worker.socket")
    fault.wait_until_succeeds(f"test -S {SOCKET}", timeout=20)

    # Build a disposable in-guest pool. Every operation below crosses the
    # production worker boundary; direct commands only arrange and observe it.
    real.succeed(f"{COREUTILS}/truncate -s 512M /run/aos/zfs-worker-pool.img")
    real.succeed(f"{ZPOOL} create -f -m none aosproof /run/aos/zfs-worker-pool.img")
    real.succeed(f"{ZFS} create -o mountpoint=none aosproof/aos")
    real.succeed(f"{ZFS} create -o mountpoint=none aosproof/aos/project")
    root_guid = guid("aosproof/aos")
    ancestor_guid = guid("aosproof/aos/project")

    run_real(f"create:{root_guid}:{ancestor_guid}:1:1:1")
    workspace_guid = guid("aosproof/aos/project/workspace")
    assert real.succeed(
        f"{ZFS} get -Hp -o value refquota aosproof/aos/project/workspace"
    ).strip() == "67108864"
    assert real.succeed(
        f"{ZFS} get -Hp -o value reservation aosproof/aos/project/workspace"
    ).strip() == "1048576"
    assert real.succeed(
        f"{ZFS} get -Hp -o value quota aosproof/aos/project"
    ).strip() == "268435456"

    run_real(f"snapshot:{root_guid}:{ancestor_guid}:{workspace_guid}:1:1")
    snapshot_guid = guid("aosproof/aos/project/workspace@revision-1")

    run_real(
        f"hold:{root_guid}:{ancestor_guid}:{workspace_guid}:{snapshot_guid}:1"
    )
    real.succeed(
        f"{ZFS} holds -H aosproof/aos/project/workspace@revision-1 "
        "| grep -F 'aos:abababababababababababababababab'"
    )

    run_real(
        f"clone:{root_guid}:{ancestor_guid}:{workspace_guid}:{snapshot_guid}:1"
    )
    clone_guid = guid("aosproof/aos/project/clone")
    assert real.succeed(
        f"{ZFS} get -Hp -o value origin aosproof/aos/project/clone"
    ).strip() == "aosproof/aos/project/workspace@revision-1"

    run_real(
        f"quota:{root_guid}:{ancestor_guid}:{workspace_guid}:{snapshot_guid}:{clone_guid}"
    )
    assert real.succeed(
        f"{ZFS} get -Hp -o value refquota aosproof/aos/project/clone"
    ).strip() == "100663296"
    assert real.succeed(
        f"{ZFS} get -Hp -o value reservation aosproof/aos/project/clone"
    ).strip() == "0"

    run_real(
        f"destroy-clone:{root_guid}:{ancestor_guid}:{workspace_guid}:{snapshot_guid}:{clone_guid}"
    )
    real.fail(f"{ZFS} list -H aosproof/aos/project/clone")
    run_real(
        f"release:{root_guid}:{ancestor_guid}:{workspace_guid}:{snapshot_guid}:1"
    )
    assert real.succeed(
        f"{ZFS} holds -H aosproof/aos/project/workspace@revision-1"
    ).strip() == ""
    run_real(
        f"destroy-snapshot:{root_guid}:{ancestor_guid}:{workspace_guid}:{snapshot_guid}:1"
    )
    real.fail(f"{ZFS} list -Ht snapshot aosproof/aos/project/workspace@revision-1")
    run_real(
        f"destroy-workspace:{root_guid}:{ancestor_guid}:{workspace_guid}:1:1"
    )
    real.fail(f"{ZFS} list -H aosproof/aos/project/workspace")

    # Repeated fast activation exercises PID 1 connection identity, worker
    # record identity, exact argv/env, and the response/ACK liveness handshake.
    fault.succeed("printf 'fast\\n' > /run/aos/zfs-worker-case")
    fault.succeed("systemctl start aos-storaged.service", timeout=30)
    wait_no_live_workers(fault)

    # A process-group-escaping descendant is still removed by the independent
    # service-cgroup deadline.
    fault.succeed(f"{COREUTILS}/rm -f ${descendantPidFile}")
    fault.succeed("printf 'timeout\\n' > /run/aos/zfs-worker-case")
    fault.succeed("systemctl start --no-block aos-storaged.service")
    fault.wait_until_succeeds(f"test -s ${descendantPidFile}", timeout=10)
    timeout_unit, timeout_cgroup = active_worker(fault)
    descendant = int(fault.succeed(f"{COREUTILS}/cat ${descendantPidFile}").strip())
    fault.wait_until_fails(
        "systemctl is-active --quiet aos-storaged.service", timeout=15
    )
    wait_worker_drained(fault, timeout_unit, timeout_cgroup)
    fault.fail(f"test -e /proc/{descendant}")

    # Killing the broker after request transmission leaves cleanup under PID 1,
    # not under the vanished broker or its process group.
    fault.succeed("systemctl reset-failed aos-storaged.service")
    fault.succeed(f"{COREUTILS}/rm -f ${descendantPidFile}")
    fault.succeed("systemctl start --no-block aos-storaged.service")
    fault.wait_until_succeeds(f"test -s ${descendantPidFile}", timeout=10)
    broker_unit, broker_cgroup = active_worker(fault)
    descendant = int(fault.succeed(f"{COREUTILS}/cat ${descendantPidFile}").strip())
    storaged = int(fault.succeed(
        "systemctl show aos-storaged.service -p MainPID --value"
    ).strip())
    assert storaged > 1, storaged
    fault.succeed(
        "systemctl kill --kill-whom=main --signal=KILL aos-storaged.service"
    )
    fault.wait_until_fails(
        "systemctl is-active --quiet aos-storaged.service", timeout=10
    )
    wait_worker_drained(fault, broker_unit, broker_cgroup)
    fault.fail(f"test -e /proc/{descendant}")
  '';
}
