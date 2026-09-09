# End-to-end proof for the fixed systemd-activated OpenZFS worker boundary.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  selectedTest = "process::tests::systemd_worker_vm_client";
  selectedPinTest = "broker::tests::systemd_workspace_pin_vm_client";
  authorityDirectory = "/run/aos/sandbox-storage-authority";
  faultStateDirectory = "/run/aos-zfs-worker-test";
  descendantPidFile = "${faultStateDirectory}/descendant.pid";

  boundaryProbe = pkgs.mkDerivation {
    pname = "aos-sandbox-storage-worker-boundary-probe";
    version = "0.1.0";
    src = null;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          $CC -std=c11 -Wall -Wextra -Werror -O2 \
            ${../sandbox/storage-worker-boundary-probe.c} \
            -o "$out/bin/storage-worker-boundary-probe"
        '';
      }
    ];
  };

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

      case "$worker_case" in
        pin:*)
          previous_ifs=$IFS
          IFS=:
          set -- $worker_case
          IFS=$previous_ifs
          test "$#" -eq 3
          exec ${pkgs.coreutils}/bin/env \
            AOS_ZFS_EXECUTABLE=${zfsPackage}/sbin/zfs \
            AOS_STORAGE_AUTHORITY_DIRECTORY=${authorityDirectory} \
            AOS_STORAGE_ROOT_GUID="$2" \
            AOS_STORAGE_ANCESTOR_GUID="$3" \
            ${fixture}/bin/aos-sandbox-zfs-worker-tests \
            --ignored --exact '${selectedPinTest}' --test-threads=1 --nocapture
          ;;
      esac

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
          {
            enable = true;
            inherit authorityDirectory;
          }
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
          RuntimeMaxSec = lib.mkForce "8s";
          ReadWritePaths = [faultStateDirectory];
          ExecStart = lib.mkForce ''
            ${pkgs.aos-landlock}/bin/aos-landlock \
              --require-abi 4 \
              --fs-read / \
              --fs-ro /nix/store \
              --fs-rw ${faultStateDirectory} \
              -- \
              ${config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-zfs-worker \
              ${selectedZfs}/sbin/zfs
          '';
        };

        systemd.services.aos-sandbox-storage-worker-boundary-probe = lib.mkIf (!faultInjection) {
          description = "Exercise Storage worker Landlock after host mount setns";
          serviceConfig = {
            Type = "oneshot";
            OpenFile = "/proc/1/ns/mnt:host-mount-namespace:read-only";
            ExecStart = ''
              ${pkgs.aos-landlock}/bin/aos-landlock \
                --require-abi 4 \
                --fs-read / \
                --fs-ro /nix/store \
                --fs-rw /dev/zfs \
                -- \
                ${boundaryProbe}/bin/storage-worker-boundary-probe
            '';
            UMask = "0077";
            User = "root";
            Group = "root";
            CapabilityBoundingSet = [
              "CAP_SYS_ADMIN"
              "CAP_SYS_CHROOT"
            ];
            AmbientCapabilities = [
              "CAP_SYS_ADMIN"
              "CAP_SYS_CHROOT"
            ];
            LimitCORE = 0;
            NoNewPrivileges = true;
            PrivateNetwork = true;
            PrivateTmp = true;
            ProcSubset = "pid";
            ProtectProc = "invisible";
            ProtectSystem = "strict";
            RestrictAddressFamilies = ["AF_UNIX"];
            RestrictNamespaces = ["mnt"];
            SystemCallArchitectures = ["native"];
            SystemCallErrorNumber = "EPERM";
            SystemCallFilter = [
              "@system-service"
              "setns"
              "landlock_create_ruleset"
              "landlock_add_rule"
              "landlock_restrict_self"
              "~mount"
              "~chmod"
              "~fchmod"
              "~fchmodat"
              "~fchmodat2"
            ];
          };
        };

        systemd.services.aos-storaged = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${runner}/bin/aos-sandbox-zfs-worker-client";
            Slice = "aos-control.slice";
            TimeoutStartSec =
              if faultInjection
              then "15s"
              else "120s";
          };
        };
      })
    ];
in {
  name = "sandbox-zfs-worker";
  timeout = 600;
  bootTimeout = 180;

  machines = {
    real = {system = makeSystem false;};
    fault = {system = makeSystem true;};
  };

  testScript = ''
    BOUNDARY_PROBE = "${boundaryProbe}/bin/storage-worker-boundary-probe"
    COREUTILS = "${pkgs.coreutils}/bin"
    FINDMNT = "${pkgs.util-linux}/bin/findmnt"
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
        assert cgroup.startswith(
            "/aos.slice/aos-control.slice/aos-sandbox-zfs-worker@"
        ), cgroup
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

    def reset_storaged_if_failed(machine):
        # `show` reloads the static unit after PID 1 collects its inactive state.
        properties = dict(
            line.split("=", 1) for line in machine.succeed(
                "systemctl show aos-storaged.service "
                "-p LoadState -p ActiveState -p SubState"
            ).splitlines()
        )
        assert properties["LoadState"] == "loaded", properties
        assert properties["ActiveState"] in ("inactive", "failed"), properties

        if properties["ActiveState"] == "failed":
            machine.succeed("systemctl reset-failed aos-storaged.service")

    def run_real(case):
        real.succeed(f"printf '%s\\n' '{case}' > /run/aos/zfs-worker-case")
        try:
            real.succeed("systemctl start aos-storaged.service", timeout=120)
        except Exception:
            diagnostics = (
                "systemctl status aos-storaged.service --no-pager --full",
                "systemctl show aos-storaged.service "
                "-p ActiveState -p SubState -p Result -p ExecMainCode "
                "-p ExecMainStatus -p ControlGroup",
                "journalctl -b -u aos-storaged.service --no-pager -o short-precise",
                f"{COREUTILS}/stat -L -c "
                "'path=%n mode=%a uid=%u gid=%g dev=%d hexdev=%D inode=%i type=%F' "
                "/run/aos/sandbox-pins/workspaces "
                "/run/aos/sandbox-pins/workspaces/*",
                f"{FINDMNT} -R /run/aos/sandbox-pins/workspaces "
                "-n -o TARGET,SOURCE,FSTYPE,FSROOT,MAJ:MIN,ID",
                "while IFS= read -r mount; do case \"$mount\" in "
                "*'/run/aos/sandbox-pins/workspaces'*) printf '%s\\n' \"$mount\";; "
                "esac; done < /proc/self/mountinfo",
                f"{ZFS} get -Hp -o name,property,value "
                "guid,mountpoint,canmount,mounted "
                "aosproof/aos/project/pinned-workspace",
                "for unit in $(systemctl list-units --all "
                "'aos-sandbox-zfs-worker@*.service' --no-legend --plain "
                "| cut -d' ' -f1); do "
                "systemctl status \"$unit\" --no-pager --full; "
                "systemctl show \"$unit\" -p ActiveState -p SubState -p Result "
                "-p ExecMainCode -p ExecMainStatus -p ControlGroup; "
                "journalctl -b -u \"$unit\" --no-pager -o short-precise; "
                "done",
                "for pattern in aos-sandbox-workspace-pin-worker@*.service "
                "aos-sandbox-workspace-pin-observer@*.service; do "
                "for unit in $(systemctl list-units --all \"$pattern\" "
                "--no-legend --plain | cut -d' ' -f1); do "
                "systemctl status \"$unit\" --no-pager --full; "
                "systemctl show \"$unit\" -p ActiveState -p SubState -p Result "
                "-p ExecMainCode -p ExecMainStatus -p ControlGroup; "
                "journalctl -b -u \"$unit\" --no-pager -o short-precise; "
                "done; done",
            )
            for command in diagnostics:
                try:
                    status, stdout, stderr = real.execute(command, timeout=20)
                    print(f"diagnostic command ({status}): {command}")
                    print(stdout.decode("utf-8", errors="replace"))
                    print(stderr.decode("utf-8", errors="replace"))
                except Exception as diagnostic_error:
                    print(
                        f"diagnostic command failed: {command}: "
                        f"{diagnostic_error}"
                    )
            raise
        wait_no_live_workers(real)

    def guid(name):
        return int(real.succeed(f"{ZFS} get -Hp -o value guid '{name}'").strip())

    for machine_name, machine in (("real", real), ("fault", fault)):
        machine.wait_for_unit("multi-user.target", timeout=120)
        machine.wait_for_unit("aos-sandbox-zfs-ready.service", timeout=20)
        machine.succeed("systemctl is-active --quiet aos-sandbox-zfs-ready.service")
        ready_properties = machine.succeed(
            "systemctl show aos-sandbox-zfs-ready.service "
            "-p ActiveState -p SubState -p Slice -p ControlGroup "
            "-p MemoryPeak -p TasksCurrent -p TasksMax"
        )
        ready_values = dict(
            line.split("=", 1) for line in ready_properties.splitlines()
        )
        print(f"{machine_name} readiness usage: {ready_values}")
        assert ready_values["ActiveState"] == "active", ready_values
        assert ready_values["SubState"] == "exited", ready_values
        assert int(ready_values["MemoryPeak"]) <= 128 * 1024 * 1024, ready_values

        assert ready_values["Slice"] == "system.slice", ready_values
        expected_ready_cgroup = "/system.slice/aos-sandbox-zfs-ready.service"
        ready_cgroup = ready_values["ControlGroup"]
        assert ready_cgroup in ("", expected_ready_cgroup), ready_values
        assert machine.succeed(
            f"{COREUTILS}/stat -fc %T /sys/fs/cgroup"
        ).strip() == "cgroup2fs"
        machine.succeed("test -d /sys/fs/cgroup/system.slice")
        machine.succeed(
            f"if test -e '/sys/fs/cgroup{expected_ready_cgroup}/cgroup.events'; then "
            f"grep -qx 'populated 0' "
            f"'/sys/fs/cgroup{expected_ready_cgroup}/cgroup.events'; "
            f"else test ! -d '/sys/fs/cgroup{expected_ready_cgroup}'; fi"
        )

        # systemd renders an empty retained cgroup as zero and a removed one as
        # "[not set]"; the cgroupfs assertion above proves both have no tasks.
        assert ready_values["TasksCurrent"] in ("0", "[not set]"), ready_values
        assert ready_values["TasksMax"] == "16", ready_values
        assert machine.succeed(
            f"{COREUTILS}/stat -c '%u:%g:%a' /dev/zfs"
        ).strip() == "0:0:666"
        machine.succeed("test -d /sys/module/zfs")
        machine.wait_until_succeeds(f"test -S {SOCKET}", timeout=20)
        for socket_unit in (
            "aos-sandbox-zfs-worker.socket",
            "aos-sandbox-workspace-pin-worker.socket",
            "aos-sandbox-workspace-pin-observer.socket",
        ):
            installed_socket = machine.succeed(f"systemctl cat '{socket_unit}'")
            accept = machine.succeed(
                f"systemctl show '{socket_unit}' -p Accept --value"
            ).strip()
            assert accept == "yes", (socket_unit, accept)
            assert "MaxConnections=1" in installed_socket, (socket_unit, installed_socket)
            assert "\nService=" not in installed_socket, (socket_unit, installed_socket)

        machine.succeed("systemctl start aos-control.slice")
        control_slice_cgroup = machine.succeed(
            "systemctl show aos-control.slice -p ControlGroup --value"
        ).strip()
        assert control_slice_cgroup == "/aos.slice/aos-control.slice", (
            machine_name,
            control_slice_cgroup,
        )
        machine.succeed(
            "test -d /sys/fs/cgroup/aos.slice/aos-control.slice"
        )
        readiness_unit = machine.succeed(
            "systemctl cat aos-sandbox-zfs-ready.service"
        )
        assert "RestrictSUIDSGID=true" in readiness_unit, readiness_unit
        for worker_unit in (
            "aos-sandbox-zfs-worker@.service",
            "aos-sandbox-workspace-pin-worker@.service",
            "aos-sandbox-workspace-pin-observer@.service",
        ):
            installed_unit = machine.succeed(f"systemctl cat '{worker_unit}'")
            assert "RestrictSUIDSGID=false" in installed_unit, (
                worker_unit,
                installed_unit,
            )
            for expected in (
                "~chmod",
                "~fchmod",
                "~fchmodat",
                "~fchmodat2",
                "LimitCORE=0",
            ):
                assert expected in installed_unit, (worker_unit, expected, installed_unit)
        selected_zfs = "${fakeZfs}/sbin/zfs" if machine_name == "fault" else ZFS
        generic_writable_path = (
            "${faultStateDirectory}" if machine_name == "fault" else "/dev/zfs"
        )
        landlock_workers = {
            "aos-sandbox-zfs-worker@.service": [
                "${pkgs.aos-landlock}/bin/aos-landlock",
                "--require-abi", "4",
                "--fs-read", "/",
                "--fs-ro", "/nix/store",
                "--fs-rw", generic_writable_path,
                "--",
                "${(makeSystem false).config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-zfs-worker",
                selected_zfs,
            ],
            "aos-sandbox-workspace-pin-observer@.service": [
                "${pkgs.aos-landlock}/bin/aos-landlock",
                "--require-abi", "4",
                "--fs-read", "/",
                "--fs-ro", "/nix/store",
                "--fs-rw", "/dev/zfs",
                "--",
                "${(makeSystem false).config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-workspace-pin-observer",
                selected_zfs,
                "${authorityDirectory}",
            ],
        }
        for worker_unit, expected_argv in landlock_workers.items():
            parsed_worker_unit = worker_unit.replace(
                "@.service", "@argv-check.service"
            )
            parsed_exec_start = machine.succeed(
                f"systemctl show '{parsed_worker_unit}' -p ExecStart --value"
            ).strip()
            assert "argv[]=" in parsed_exec_start, (worker_unit, parsed_exec_start)
            argv_field = parsed_exec_start.split("argv[]=", 1)[1].split(" ;", 1)[0]
            assert argv_field.split() == expected_argv, (
                worker_unit,
                expected_argv,
                parsed_exec_start,
            )

            installed_unit = machine.succeed(f"systemctl cat '{worker_unit}'")
            for expected in (
                "landlock_create_ruleset",
                "landlock_add_rule",
                "landlock_restrict_self",
            ):
                assert expected in installed_unit, (worker_unit, expected, installed_unit)
        effect_unit = machine.succeed(
            "systemctl cat 'aos-sandbox-workspace-pin-worker@.service'"
        )
        assert "aos-landlock" not in effect_unit, effect_unit
        generic_unit = machine.succeed(
            "systemctl cat 'aos-sandbox-zfs-worker@.service'"
        )
        for expected in (
            "User=aos-sandbox-zfs-worker",
            "Group=aos-sandbox-zfs-worker",
            "LimitCORE=0",
        ):
            assert expected in generic_unit, (expected, generic_unit)
        worker_uid = machine.succeed(
            f"{COREUTILS}/id -u aos-sandbox-zfs-worker"
        ).strip()
        worker_gid = machine.succeed(
            f"{COREUTILS}/id -g aos-sandbox-zfs-worker"
        ).strip()
        assert worker_uid == "992", worker_uid
        assert worker_gid == "992", worker_gid

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

    # The installed storaged fixture mints real protected records, then drives
    # the serialized static-identity worker and descriptor-backed root worker through
    # one complete create, Ensure, ordinary-unmount, and destroy lifecycle.
    real.succeed(
        f"{COREUTILS}/mkdir -p /run/aos/sandbox-pins/workspaces "
        "${authorityDirectory}"
    )
    real.succeed(
        f"{COREUTILS}/chmod 0700 /run/aos/sandbox-pins/workspaces "
        "${authorityDirectory}"
    )
    # This succeeds in the host namespace before the service starts, so the
    # probe's later failures are policy denials rather than a read-only /run.
    real.succeed("printf candidate > /run/aos-storage-worker-setid-denied")
    real.succeed("chmod 0600 /run/aos-storage-worker-setid-denied")

    def require_probe_failure(command, expected_diagnostic):
        status, stdout, stderr = real.execute(command, timeout=20)
        decoded_stdout = stdout.decode("utf-8", errors="replace")
        decoded_stderr = stderr.decode("utf-8", errors="replace")
        print(f"boundary negative command ({status}): {command}")
        print(decoded_stdout)
        print(decoded_stderr)
        assert status != 0, (command, decoded_stdout, decoded_stderr)
        assert expected_diagnostic in decoded_stderr, (
            command,
            expected_diagnostic,
            decoded_stderr,
        )

    contract_diagnostic = "unexpected systemd file descriptor contract"
    require_probe_failure(BOUNDARY_PROBE, contract_diagnostic)
    require_probe_failure(
        f"exec 3</proc/self/ns/mnt; exec {COREUTILS}/env "
        f"LISTEN_PID=$$ LISTEN_FDS=2 "
        f"LISTEN_FDNAMES=host-mount-namespace {BOUNDARY_PROBE}",
        contract_diagnostic,
    )
    require_probe_failure(
        f"exec 3</proc/self/ns/mnt; exec {COREUTILS}/env "
        f"LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=wrong {BOUNDARY_PROBE}",
        contract_diagnostic,
    )
    require_probe_failure(
        f"exec 3</etc/os-release; exec {COREUTILS}/env "
        f"LISTEN_PID=$$ LISTEN_FDS=1 "
        f"LISTEN_FDNAMES=host-mount-namespace {BOUNDARY_PROBE}",
        "mount namespace descriptor is not on nsfs",
    )

    try:
        real.succeed(
            "systemctl start aos-sandbox-storage-worker-boundary-probe.service"
        )
    except Exception:
        for command in (
            "systemctl status aos-sandbox-storage-worker-boundary-probe.service "
            "--no-pager --full",
            "systemctl show aos-sandbox-storage-worker-boundary-probe.service "
            "-p ActiveState -p SubState -p Result -p ExecMainCode "
            "-p ExecMainStatus -p ControlGroup",
            "journalctl -b -u aos-sandbox-storage-worker-boundary-probe.service "
            "--no-pager -o short-precise",
        ):
            try:
                status, stdout, stderr = real.execute(command, timeout=20)
                print(f"boundary diagnostic command ({status}): {command}")
                print(stdout.decode("utf-8", errors="replace"))
                print(stderr.decode("utf-8", errors="replace"))
            except Exception as diagnostic_error:
                print(
                    f"boundary diagnostic command failed: {command}: "
                    f"{diagnostic_error}"
                )
        raise
    real.succeed("test $(stat -c %a /run/aos-storage-worker-setid-denied) = 600")
    real.fail("test -e /run/aos-storage-worker-host-write-denied")
    real.fail("test -e /run/aos-storage-worker-direct-setid-denied")
    run_real(f"pin:{root_guid}:{ancestor_guid}")
    datasets_after_pin_test = real.succeed(f"{ZFS} list -H -o name").splitlines()
    assert "aosproof/aos/project/pinned-workspace" not in datasets_after_pin_test, (
        datasets_after_pin_test
    )
    assert "aosproof/aos/project/observed-workspace" in datasets_after_pin_test, (
        datasets_after_pin_test
    )
    real.succeed(
        "test $(find /var/lib/aos-sandbox-workspace-pin-worker "
        "-maxdepth 1 -name 'attempt-*' -type f | wc -l) -eq 2"
    )
    observer_unit = real.succeed(
        "systemctl cat aos-sandbox-workspace-pin-observer@.service"
    )
    for denied_call in (
        "~mount",
        "~umount2",
        "~fsopen",
        "~fsmount",
        "~move_mount",
        "~mount_setattr",
    ):
        assert denied_call in observer_unit, (denied_call, observer_unit)
    for pattern in (
        "aos-sandbox-workspace-pin-worker@*.service",
        "aos-sandbox-workspace-pin-observer@*.service",
    ):
        real.wait_until_succeeds(
            "for unit in $(systemctl list-units --all "
            f"'{pattern}' --no-legend --plain | cut -d' ' -f1); do "
            "state=$(systemctl show \"$unit\" -p ActiveState --value); "
            "test \"$state\" = inactive -o \"$state\" = failed || exit 1; "
            "done",
            timeout=15,
        )
    real.succeed(f"{ZFS} destroy aosproof/aos/project/observed-workspace")
    datasets_after_observer_cleanup = real.succeed(
        f"{ZFS} list -H -o name"
    ).splitlines()
    assert "aosproof/aos/project/observed-workspace" not in (
        datasets_after_observer_cleanup
    ), datasets_after_observer_cleanup

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
    timeout_properties = fault.succeed(
        f"systemctl show '{timeout_unit}' "
        "-p User -p Group -p DynamicUser -p RestrictSUIDSGID -p LimitCORE "
        "-p MainPID"
    )
    timeout_values = dict(
        line.split("=", 1) for line in timeout_properties.splitlines()
    )
    assert timeout_values["User"] == "aos-sandbox-zfs-worker", timeout_values
    assert timeout_values["Group"] == "aos-sandbox-zfs-worker", timeout_values
    assert timeout_values["DynamicUser"] == "no", timeout_values
    assert timeout_values["RestrictSUIDSGID"] == "no", timeout_values
    assert timeout_values["LimitCORE"] == "0", timeout_values
    worker_pid = int(timeout_values["MainPID"])
    assert worker_pid > 1, timeout_values
    assert fault.succeed(
        f"{COREUTILS}/stat -c '%u:%g' /proc/{worker_pid}"
    ).strip() == "992:992"
    descendant = int(fault.succeed(f"{COREUTILS}/cat ${descendantPidFile}").strip())
    fault.wait_until_fails(
        "systemctl is-active --quiet aos-storaged.service", timeout=15
    )
    wait_worker_drained(fault, timeout_unit, timeout_cgroup)
    fault.fail(f"test -e /proc/{descendant}")

    # Killing the broker after request transmission leaves cleanup under PID 1,
    # not under the vanished broker or its process group.
    reset_storaged_if_failed(fault)
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

    # Closing the first client does not release the Accept=yes connection
    # while its worker cgroup remains populated. A second valid storaged client
    # is rejected rather than overlapping under the stable worker UID.
    fault.succeed(f"test -e /proc/{descendant}")
    socket_counts_before = dict(
        line.split("=", 1) for line in fault.succeed(
            "systemctl show aos-sandbox-zfs-worker.socket "
            "-p NConnections -p NAccepted -p NRefused"
        ).splitlines()
    )
    assert socket_counts_before["NConnections"] == "1", socket_counts_before
    fault.succeed("printf 'fast\n' > /run/aos/zfs-worker-case")
    reset_storaged_if_failed(fault)
    fault.fail("systemctl start aos-storaged.service", timeout=3)
    socket_counts_after = dict(
        line.split("=", 1) for line in fault.succeed(
            "systemctl show aos-sandbox-zfs-worker.socket "
            "-p NConnections -p NAccepted -p NRefused"
        ).splitlines()
    )
    assert socket_counts_after["NConnections"] == "1", socket_counts_after
    assert int(socket_counts_after["NAccepted"]) == int(
        socket_counts_before["NAccepted"]
    ), (socket_counts_before, socket_counts_after)
    assert int(socket_counts_after["NRefused"]) == int(
        socket_counts_before["NRefused"]
    ) + 1, (socket_counts_before, socket_counts_after)
    overlapping_unit, overlapping_cgroup = active_worker(fault)
    assert overlapping_unit == broker_unit, (overlapping_unit, broker_unit)
    assert overlapping_cgroup == broker_cgroup, (overlapping_cgroup, broker_cgroup)
    fault.succeed(f"test -e /proc/{descendant}")

    wait_worker_drained(fault, broker_unit, broker_cgroup)
    fault.fail(f"test -e /proc/{descendant}")
    reset_storaged_if_failed(fault)
    fault.succeed("systemctl start aos-storaged.service", timeout=15)
    wait_no_live_workers(fault)
  '';
}
