# Installed systemd boundary proof for the nonauthorizing held-snapshot reader.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  clientTest = "process::held_snapshot_reader::tests::systemd_reader_vm_client";
  decoyTest = "process::held_snapshot_reader::tests::systemd_reader_vm_decoy";
  crossingTest = "process::held_snapshot_reader::tests::systemd_reader_vm_mount_crossings";
  confinementTest = "process::held_snapshot_reader::vm_tests::installed_confinement";
  controllerTest = "process::held_snapshot_reader::vm_tests::controller_denials";

  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-held-snapshot-reader-tests";
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
      mkdir fixture-bin
      count=0
      for candidate in target/debug/deps/aos_sandbox_storage-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" fixture-bin/aos-sandbox-held-snapshot-reader-tests
          count=$((count + 1))
        fi
      done
      test "$count" -eq 1
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 \
        fixture-bin/aos-sandbox-held-snapshot-reader-tests \
        "$out/bin/"
    '';
  };

  system = mkSystem [
    ../../systems/server-test.nix
    ({config, ...}: let
      zfs = pkgs.zfsForKernel config.system.build.kernel;
      runFixture = selectedTest: "${fixture}/bin/aos-sandbox-held-snapshot-reader-tests --ignored --exact ${selectedTest} --test-threads=1 --nocapture";
    in {
      aos.sandbox.storageWorker.enable = true;
      aos.image.budgets = {
        maxRootMiB = 1024;
        maxDownloadMiB = 1152;
      };
      environment.systemPackages = [pkgs.coreutils pkgs.systemd pkgs.util-linux zfs];

      # The probe inherits the unchanged production template's restrictions.
      # Keep test-harness output on the journal, never on the protocol socket.
      systemd.services."aos-sandbox-held-snapshot-reader@".serviceConfig.ExecStartPre = "${pkgs.bash}/bin/bash -c '${runFixture confinementTest} >&2'";

      aos.users.users.aos-sandboxd = {
        uid = config.aos.sandbox.controller.uid;
        group = "aos-sandboxd";
        home = "/var/lib/aos/sandboxd";
        shell = "/sbin/nologin";
        extraGroups = [];
      };
      aos.users.groups.aos-sandboxd.gid = config.aos.sandbox.controller.gid;
      systemd.services.aos-sandboxd = {
        description = "Held reader unauthorized Controller fixture";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = runFixture controllerTest;
          User = "aos-sandboxd";
          Group = "aos-sandboxd";
          Slice = "aos-control.slice";
          Environment = [
            "AOS_HELD_READER_SYSTEMCTL=${pkgs.systemd}/bin/systemctl"
            "AOS_HELD_READER_CONTROLLER_UID=${toString config.aos.sandbox.controller.uid}"
            "AOS_HELD_READER_CONTROLLER_GID=${toString config.aos.sandbox.controller.gid}"
          ];
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateNetwork = true;
          ProtectSystem = "strict";
          ProtectControlGroups = true;
          StandardOutput = "append:/run/aos-held-controller-output";
          StandardError = "append:/run/aos-held-controller-output";
        };
      };
      systemd.services.aos-held-reader-mutation-decoy = {
        description = "Disposable unit for unauthorized management probes";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.coreutils}/bin/touch /run/aos-held-reader-forbidden-start";
          TasksMax = 16;
        };
      };

      # This test-only caller has the exact protected owner's cgroup identity,
      # but does not claim to construct or retain its journal cut.
      systemd.services.aos-storaged = {
        description = "Held snapshot reader VM client";
        requires = ["aos-sandbox-zfs-ready.service"];
        after = ["aos-sandbox-zfs-ready.service"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = runFixture clientTest;
          User = "root";
          Group = "root";
          StateDirectory = "aos/sandbox-storage";
          StateDirectoryMode = "0700";
          Slice = "aos-control.slice";
          StandardOutput = "append:/run/aos-held-client-output";
          StandardError = "append:/run/aos-held-client-output";
        };
      };

      systemd.services.aos-held-reader-decoy = {
        description = "Wrong-cgroup held snapshot reader VM client";
        requires = ["aos-sandbox-zfs-ready.service"];
        after = ["aos-sandbox-zfs-ready.service"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = runFixture decoyTest;
          User = "root";
          Group = "root";
          Slice = "aos-control.slice";
          StandardOutput = "append:/run/aos-held-decoy-output";
          StandardError = "append:/run/aos-held-decoy-output";
        };
      };
    })
  ];
  zfs = pkgs.zfsForKernel system.config.system.build.kernel;
in {
  name = "sandbox-held-snapshot-reader";
  timeout = 420;
  bootTimeout = 180;

  machines.vm = {inherit system;};

  testScript = ''
    ZFS = "${zfs}/sbin/zfs"
    ZPOOL = "${zfs}/sbin/zpool"
    TRUNCATE = "${pkgs.coreutils}/bin/truncate"
    FINDMNT = "${pkgs.util-linux}/bin/findmnt"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    UMOUNT = "${pkgs.util-linux}/bin/umount"
    UNSHARE = "${pkgs.util-linux}/bin/unshare"
    SNAPSHOT = "aosproof/aos/project/workspace@held"
    SOCKET = "aos-sandbox-held-snapshot-reader.socket"

    def guid(name):
        return int(vm.succeed(f"{ZFS} get -Hp -o value guid '{name}'").strip())

    def accepted():
        return int(vm.succeed(f"systemctl show {SOCKET} -p NAccepted --value").strip())

    def reader_properties():
        properties = (
            "User", "Group", "PrivateDevices", "PrivateMounts", "PrivateNetwork",
            "NoNewPrivileges", "ProtectSystem", "ProtectControlGroups", "DevicePolicy",
            "CapabilityBoundingSet", "AmbientCapabilities", "StandardOutput", "StandardError",
            "TasksMax", "ExecStart", "ExecStartPre", "FragmentPath", "DropInPaths",
        )
        arguments = " ".join(f"-p {name}" for name in properties)
        return dict(line.split("=", 1) for line in vm.succeed(
            f"systemctl show 'aos-sandbox-held-snapshot-reader@.service' {arguments}"
        ).splitlines())

    def run_case(variant, pool_guid, root_guid, dataset_guid, snapshot_guid):
        vm.succeed(
            "printf '%s\\n' "
            f"'{variant}:{pool_guid}:{root_guid}:{dataset_guid}:{snapshot_guid}' "
            "> /run/aos/held-reader-case"
        )
        before = accepted()
        try:
            vm.succeed("systemctl start aos-storaged.service", timeout=85)
        except Exception:
            for command in (
                "systemctl status aos-storaged.service --no-pager -l",
                "systemctl list-units --all 'aos-sandbox-held-snapshot-reader@*.service' --no-pager",
                "journalctl -b -u aos-storaged.service --no-pager -o cat",
                "test -e /run/aos-held-client-output && cat /run/aos-held-client-output",
                "journalctl -b --no-pager -o cat | tail -n 120",
            ):
                status, output, error = vm.execute(command, timeout=20)
                print(f"diagnostic ({status}): {command}")
                print(output.decode("utf-8", errors="replace"))
                print(error.decode("utf-8", errors="replace"))
            raise
        assert accepted() == before + 1, (variant, before, accepted())

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.wait_for_unit("aos-sandbox-zfs-ready.service", timeout=30)
    vm.wait_for_unit(SOCKET, timeout=30)

    unit = vm.succeed("systemctl cat 'aos-sandbox-held-snapshot-reader@.service'")
    for setting in (
        "PrivateDevices=true",
        "PrivateMounts=true",
        "DevicePolicy=closed",
        "CapabilityBoundingSet=CAP_SYS_ADMIN",
        "StandardOutput=socket",
        "StandardError=journal",
        "TemporaryFileSystem=/run/aos-held-reader-namespace:ro,nosuid,nodev,noexec",
        "~move_mount",
        "~setns",
    ):
        assert setting in unit, (setting, unit)
    assert "DeviceAllow=" not in unit, unit
    assert "StandardError=append:" not in unit, unit

    effective = reader_properties()
    for name in ("PrivateDevices", "PrivateMounts", "PrivateNetwork", "NoNewPrivileges", "ProtectControlGroups"):
        assert effective[name] == "yes", (name, effective)
    assert effective["User"] == effective["Group"] == "root", effective
    assert effective["CapabilityBoundingSet"] == effective["AmbientCapabilities"] == "cap_sys_admin", effective
    assert effective["DevicePolicy"] == "closed", effective
    assert effective["ProtectSystem"] == "strict", effective
    assert effective["TasksMax"] == "4", effective
    assert effective["StandardOutput"] == "socket" and effective["StandardError"] == "journal", effective
    assert "${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-held-snapshot-reader" in effective["ExecStart"], effective
    reader_binary_hash = vm.succeed("${pkgs.coreutils}/bin/sha256sum ${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-held-snapshot-reader")

    vm.succeed(f"{TRUNCATE} -s 1G /var/tmp/aos-held-reader.pool")
    vm.succeed(f"{ZPOOL} create -f -m none -o cachefile=none aosproof /var/tmp/aos-held-reader.pool")
    vm.succeed(f"{ZFS} create -o mountpoint=none -o canmount=off aosproof/aos")
    vm.succeed(f"{ZFS} create -o mountpoint=none -o canmount=off aosproof/aos/project")
    vm.succeed(
        f"{ZFS} create -o mountpoint=/var/tmp/aos-held-reader-root "
        "aosproof/aos/project/workspace"
    )
    vm.succeed("printf 'held reader service payload\\n' > /var/tmp/aos-held-reader-root/payload")
    vm.succeed("${pkgs.coreutils}/bin/chown 42:43 /var/tmp/aos-held-reader-root/payload")
    vm.succeed("${pkgs.coreutils}/bin/chmod 755 /var/tmp/aos-held-reader-root")
    vm.succeed("${pkgs.coreutils}/bin/chmod 644 /var/tmp/aos-held-reader-root/payload")
    vm.succeed("mkdir -p /var/tmp/aos-held-reader-root/nested/deeper")
    vm.succeed("printf abc > /var/tmp/aos-held-reader-root/nested/deeper/data")
    vm.succeed("${pkgs.coreutils}/bin/chmod 755 /var/tmp/aos-held-reader-root/nested /var/tmp/aos-held-reader-root/nested/deeper")
    vm.succeed("${pkgs.coreutils}/bin/chmod 644 /var/tmp/aos-held-reader-root/nested/deeper/data")
    vm.succeed(f"{ZFS} snapshot {SNAPSHOT}")
    vm.succeed(f"{ZFS} hold aos-sbx-reader-vm {SNAPSHOT}")

    pool_guid = int(vm.succeed(f"{ZPOOL} get -Hp -o value guid aosproof").strip())
    root_guid = guid("aosproof/aos")
    dataset_guid = guid("aosproof/aos/project/workspace")
    snapshot_guid = guid(SNAPSHOT)

    run_case("matched", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("wrong-pool", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("wrong-snapshot", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("matched-mount", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("wrong-pool-mount", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("wrong-snapshot-mount", pool_guid, root_guid, dataset_guid, snapshot_guid)

    # A live same-filesystem bind changes the pathname view, not the held
    # snapshot. The reader must create a fresh fscontext, never clone that view.
    vm.succeed("mkdir /var/tmp/aos-held-reader-root/overlay-source")
    vm.succeed("printf decoy > /var/tmp/aos-held-reader-root/overlay-source/data")
    vm.succeed(f"{MOUNT} --bind /var/tmp/aos-held-reader-root/overlay-source /var/tmp/aos-held-reader-root/nested/deeper")
    try:
        assert vm.succeed("cat /var/tmp/aos-held-reader-root/nested/deeper/data") == "decoy"
        run_case("matched-mount", pool_guid, root_guid, dataset_guid, snapshot_guid)
    finally:
        vm.succeed(f"{UMOUNT} /var/tmp/aos-held-reader-root/nested/deeper")

    # This deliberately modified walk is separate from genuine reader custody.
    # Attachments exist only in this VM-only private namespace; no receipt,
    # journal cut, signing, or native Acquire authority is constructed here.
    vm.succeed(
        f"{UNSHARE} --mount --propagation private "
        "${fixture}/bin/aos-sandbox-held-snapshot-reader-tests "
        "--ignored --exact ${crossingTest} --test-threads=1 --nocapture",
        timeout=85,
    )

    # Keep the exact Storage cgroup alive while the decoy connects. Otherwise
    # the reader correctly fails at a missing owner anchor before peer matching.
    vm.succeed("mkdir -p /run/systemd/system/aos-storaged.service.d")
    vm.succeed(
        "printf '[Service]\\nExecStartPost=${pkgs.coreutils}/bin/sleep 60\\n' "
        "> /run/systemd/system/aos-storaged.service.d/retained.conf"
    )
    vm.succeed("systemctl daemon-reload")
    vm.succeed("systemctl start --no-block aos-storaged.service")
    vm.wait_until_succeeds(
        "test $(systemctl show aos-storaged.service -p SubState --value) = start-post",
        timeout=10,
    )

    before = accepted()
    vm.succeed("systemctl start aos-held-reader-decoy.service", timeout=30)
    assert accepted() == before + 1, (before, accepted())

    # A real cap-empty non-root Controller cannot replace the reader fragment,
    # change management properties, enter Storage's cgroup, or use its socket.
    vm.succeed("mkdir -p /run/systemd/system/aos-sandbox-held-snapshot-reader@.service.d")
    vm.succeed("${pkgs.coreutils}/bin/chmod 755 /run/systemd/system/aos-sandbox-held-snapshot-reader@.service.d")
    before_denial = reader_properties()
    decoy_properties = vm.succeed("systemctl show aos-held-reader-mutation-decoy.service -p TasksMax -p ExecStart -p FragmentPath")
    vm.succeed("systemctl start aos-sandboxd.service", timeout=30)
    assert reader_properties() == before_denial
    assert vm.succeed("systemctl show aos-held-reader-mutation-decoy.service -p TasksMax -p ExecStart -p FragmentPath") == decoy_properties
    assert vm.succeed("${pkgs.coreutils}/bin/sha256sum ${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-held-snapshot-reader") == reader_binary_hash
    vm.fail("test -e /run/aos-held-reader-forbidden-start")
    vm.fail("test -e /run/systemd/system/aos-sandbox-held-snapshot-reader@.service.d/unauthorized.conf")
    vm.fail("test -e /etc/systemd/system/aos-held-reader-unauthorized.service")
    assert accepted() == before + 1
    assert "test result: ok" in vm.succeed("cat /run/aos-held-controller-output")
    vm.succeed("systemctl stop aos-storaged.service")

    client_output = vm.succeed("cat /run/aos-held-client-output")
    decoy_output = vm.succeed("cat /run/aos-held-decoy-output")
    assert client_output.count("test result: ok") >= 8, client_output
    assert "test result: ok" in decoy_output, decoy_output
    assert "aos-sbx-reader-vm" in vm.succeed(f"{ZFS} holds -H {SNAPSHOT}")
    assert vm.succeed(
        f"{FINDMNT} -n -o SOURCE --target /var/tmp/aos-held-reader-root"
    ).strip() == "aosproof/aos/project/workspace"
  '';
}
