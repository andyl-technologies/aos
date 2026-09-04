# Executable RFC-0019 storage-substrate proof against kernel-matched OpenZFS.
{
  mkSystem,
  pkgs,
  ...
}: let
  idmappedMountProbe = pkgs.mkDerivation {
    pname = "aos-zfs-idmapped-mount-probe";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            ${../sandbox/zfs-idmapped-mount-probe.c} \
            -o aos-zfs-idmapped-mount-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-zfs-idmapped-mount-probe $out/bin/
        '';
      }
    ];
    meta = {
      description = "Runtime proof for idmapped mounts over an AOS ZFS dataset";
      license = "Apache-2.0";
    };
  };

  system = mkSystem [
    ../../systems/server-test.nix
    ({config, ...}: let
      zfs = pkgs.zfsForKernel config.system.build.kernel;
    in {
      aos.kernel.modulePackages = [zfs];
      aos.kernel.modules = ["zfs"];
      aos.image.budgets = {
        maxRootMiB = 1024;
        maxDownloadMiB = 1152;
      };
      environment.systemPackages = [
        idmappedMountProbe
        pkgs.coreutils
        pkgs.jq
        pkgs.kmod
        pkgs.util-linux
        zfs
      ];
    })
  ];
  zfs = pkgs.zfsForKernel system.config.system.build.kernel;
in {
  name = "sandbox-zfs-platform-proof";
  timeout = 900;
  bootTimeout = 180;

  machines.vm = {inherit system;};

  testScript =
    # python
    ''
      import json

      ZFS = "${zfs}/sbin/zfs"
      ZPOOL = "${zfs}/sbin/zpool"
      MODPROBE = "${pkgs.kmod}/bin/modprobe"
      TRUNCATE = "${pkgs.coreutils}/bin/truncate"
      DD = "${pkgs.coreutils}/bin/dd"
      RM = "${pkgs.coreutils}/bin/rm"
      UNAME = "${pkgs.coreutils}/bin/uname"
      STAT = "${pkgs.coreutils}/bin/stat"
      UMOUNT = "${pkgs.util-linux}/bin/umount"
      JQ = "${pkgs.jq}/bin/jq"
      PROBE = "${idmappedMountProbe}/bin/aos-zfs-idmapped-mount-probe"
      REPORT = "/var/tmp/aos-zfs-platform-proof.json"

      vm.wait_for_unit("multi-user.target", timeout=120)
      vm.succeed(f"{MODPROBE} zfs")
      vm.succeed(f"test -d /sys/module/zfs")
      vm.succeed(f"{TRUNCATE} -s 1G /var/tmp/aos-zfs-platform-proof.pool")
      vm.succeed(
          f"{ZPOOL} create -f -m none -o cachefile=none "
          "aosproof /var/tmp/aos-zfs-platform-proof.pool"
      )
      vm.succeed("mkdir -p /mnt/aos-zfs-source /mnt/aos-zfs-clone /mnt/aos-zfs-idmap")
      vm.succeed(
          f"{ZFS} create -o mountpoint=/mnt/aos-zfs-source "
          "-o quota=64M aosproof/source"
      )
      vm.succeed("printf 'immutable snapshot payload\\n' > /mnt/aos-zfs-source/payload")

      vm.succeed(f"{ZFS} snapshot aosproof/source@base")
      vm.succeed(f"{ZFS} hold aos-sbx-p0-07 aosproof/source@base")
      holds = vm.succeed(f"{ZFS} holds -H aosproof/source@base")
      assert "aos-sbx-p0-07" in holds, holds
      vm.fail(f"{ZFS} destroy aosproof/source@base")

      vm.succeed(
          f"{ZFS} clone -o mountpoint=/mnt/aos-zfs-clone "
          "aosproof/source@base aosproof/clone"
      )
      assert vm.succeed("cat /mnt/aos-zfs-clone/payload") == "immutable snapshot payload\n"
      quota = int(vm.succeed(f"{ZFS} get -Hp -o value quota aosproof/source").strip())
      allocation_before, free_before = map(
          int,
          vm.succeed(f"{ZPOOL} list -Hp -o allocated,free aosproof").split(),
      )
      vm.succeed(f"{ZFS} set reservation=16M aosproof/source")
      allocation_after, free_after = map(
          int,
          vm.succeed(f"{ZPOOL} list -Hp -o allocated,free aosproof").split(),
      )
      reservation = int(
          vm.succeed(f"{ZFS} get -Hp -o value reservation aosproof/source").strip()
      )
      assert quota == 64 * 1024 * 1024, quota
      assert reservation == 16 * 1024 * 1024, reservation
      assert allocation_after > allocation_before, (allocation_before, allocation_after)
      assert free_after < free_before, (free_before, free_after)
      reservation_accounted_bytes = allocation_after - allocation_before
      assert reservation_accounted_bytes >= 15 * 1024 * 1024, reservation_accounted_bytes

      vm.fail(
          f"{DD} if=/dev/urandom of=/mnt/aos-zfs-source/quota-fill "
          "bs=1M count=80 status=none conv=fsync"
      )
      quota_used = int(vm.succeed(f"{ZFS} get -Hp -o value used aosproof/source").strip())
      assert quota_used <= quota, (quota_used, quota)
      vm.succeed(f"{RM} -f /mnt/aos-zfs-source/quota-fill")

      vm.succeed(
          f"{ZFS} send aosproof/source@base | "
          f"{ZFS} receive -o mountpoint=/mnt/aos-zfs-received aosproof/received"
      )
      assert vm.succeed("cat /mnt/aos-zfs-received/payload") == "immutable snapshot payload\n"
      received_name = vm.succeed(
          f"{ZFS} list -Hp -o name aosproof/received"
      ).strip()
      assert received_name == "aosproof/received", received_name
      source_guid = vm.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/source@base"
      ).strip()
      received_guid = vm.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/received@base"
      ).strip()
      assert received_guid == source_guid, (source_guid, received_guid)

      idmap = json.loads(
          vm.succeed(
              f"{PROBE} /mnt/aos-zfs-source /mnt/aos-zfs-idmap "
              "/mnt/aos-zfs-source/payload"
          )
      )
      assert idmap == {
          "schema_version": "aos.sandbox.zfs-idmapped-mount/v1",
          "source_uid": 100000,
          "source_gid": 100000,
          "mapped_uid": 0,
          "mapped_gid": 0,
          "idmapped_mount": True,
      }, idmap

      vm.succeed(
          f"{JQ} -n --arg architecture \"$({UNAME} -m)\" "
          f"--arg zfs_version \"$({ZFS} version -H | ${pkgs.coreutils}/bin/head -n 1)\" "
          "'{schema_version:\"aos.sandbox.zfs-platform-proof/v1\",evidence_version:1,"
          "architecture:$architecture,zfs_version:$zfs_version,"
          "behaviors:{snapshot:true,hold:true,hold_blocks_destroy:true,clone:true,"
          "quota_property:true,quota_enforced:true,reservation_property:true,"
          "reservation_accounted:true,send_receive:true,received_snapshot_identity:true,"
          "idmapped_mount:true}}' "
          f"> {REPORT}"
      )
      report_size = int(vm.succeed(f"{STAT} -c %s {REPORT}").strip())
      assert 0 < report_size <= 16384, report_size
      report = json.loads(vm.succeed(f"cat {REPORT}"))
      assert report["schema_version"] == "aos.sandbox.zfs-platform-proof/v1", report
      assert report["evidence_version"] == 1, report
      assert report["architecture"] in ("x86_64", "aarch64"), report
      assert report["zfs_version"].startswith("zfs-2.4.0"), report
      assert all(report["behaviors"].values()), report

      vm.succeed(f"{ZPOOL} status -x aosproof")
      vm.succeed(f"{UMOUNT} /mnt/aos-zfs-idmap")
      vm.succeed(f"{ZPOOL} destroy aosproof")
      vm.succeed(f"{RM} -f /var/tmp/aos-zfs-platform-proof.pool")
    '';
}
