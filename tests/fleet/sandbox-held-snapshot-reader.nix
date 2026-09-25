# Installed systemd boundary proof for the nonauthorizing held-snapshot reader.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  clientTest = "process::held_snapshot_reader::tests::systemd_reader_vm_client";
  decoyTest = "process::held_snapshot_reader::tests::systemd_reader_vm_decoy";

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
      runFixture = selectedTest:
        "${fixture}/bin/aos-sandbox-held-snapshot-reader-tests --ignored --exact ${selectedTest} --test-threads=1 --nocapture";
    in {
      aos.sandbox.storageWorker.enable = true;
      aos.image.budgets = {
        maxRootMiB = 1024;
        maxDownloadMiB = 1152;
      };
      environment.systemPackages = [pkgs.coreutils pkgs.systemd pkgs.util-linux zfs];

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
    SNAPSHOT = "aosproof/aos/project/workspace@held"
    SOCKET = "aos-sandbox-held-snapshot-reader.socket"

    def guid(name):
        return int(vm.succeed(f"{ZFS} get -Hp -o value guid '{name}'").strip())

    def accepted():
        return int(vm.succeed(f"systemctl show {SOCKET} -p NAccepted --value").strip())

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

    vm.succeed(f"{TRUNCATE} -s 1G /var/tmp/aos-held-reader.pool")
    vm.succeed(f"{ZPOOL} create -f -m none -o cachefile=none aosproof /var/tmp/aos-held-reader.pool")
    vm.succeed(f"{ZFS} create -o mountpoint=none -o canmount=off aosproof/aos")
    vm.succeed(f"{ZFS} create -o mountpoint=none -o canmount=off aosproof/aos/project")
    vm.succeed(
        f"{ZFS} create -o mountpoint=/var/tmp/aos-held-reader-root "
        "aosproof/aos/project/workspace"
    )
    vm.succeed("printf 'held reader service payload\\n' > /var/tmp/aos-held-reader-root/payload")
    vm.succeed(f"{ZFS} snapshot {SNAPSHOT}")
    vm.succeed(f"{ZFS} hold aos-sbx-reader-vm {SNAPSHOT}")

    pool_guid = int(vm.succeed(f"{ZPOOL} get -Hp -o value guid aosproof").strip())
    root_guid = guid("aosproof/aos")
    dataset_guid = guid("aosproof/aos/project/workspace")
    snapshot_guid = guid(SNAPSHOT)

    run_case("matched", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("wrong-pool", pool_guid, root_guid, dataset_guid, snapshot_guid)
    run_case("wrong-snapshot", pool_guid, root_guid, dataset_guid, snapshot_guid)

    # Keep the exact Storage cgroup alive while the decoy connects. Otherwise
    # the reader correctly fails at a missing owner anchor before peer matching.
    vm.succeed("mkdir -p /run/systemd/system/aos-storaged.service.d")
    vm.succeed(
        "printf '[Service]\\nExecStartPost=${pkgs.coreutils}/bin/sleep 15\\n' "
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
    vm.succeed("systemctl stop aos-storaged.service")

    client_output = vm.succeed("cat /run/aos-held-client-output")
    decoy_output = vm.succeed("cat /run/aos-held-decoy-output")
    assert client_output.count("test result: ok") >= 4, client_output
    assert "test result: ok" in decoy_output, decoy_output
    assert "aos-sbx-reader-vm" in vm.succeed(f"{ZFS} holds -H {SNAPSHOT}")
    assert vm.succeed(
        f"{FINDMNT} -n -o SOURCE --target /var/tmp/aos-held-reader-root"
    ).strip() == "aosproof/aos/project/workspace"
  '';
}
