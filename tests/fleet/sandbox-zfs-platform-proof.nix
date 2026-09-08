# Executable RFC-0020 storage-substrate proof against kernel-matched OpenZFS.
{
  mkSystem,
  pkgs,
  ...
}: let
  idmappedMountProbe = pkgs.mkDerivation {
    pname = "aos-zfs-idmapped-mount-probe";
    version = "1";
    src = null;
    # Kernel UAPI is a target input; buildDeps would splice native headers.
    runtimeDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            -I${pkgs.linux-headers}/include \
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

  fsopenMountProbe = pkgs.mkDerivation {
    pname = "aos-zfs-fsopen-mount-probe";
    version = "1";
    src = null;
    # Kernel UAPI is a target input; buildDeps would splice native headers.
    runtimeDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            -I${pkgs.linux-headers}/include \
            ${../sandbox/zfs-fsopen-mount-probe.c} \
            -o aos-zfs-fsopen-mount-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-zfs-fsopen-mount-probe $out/bin/
        '';
      }
    ];
    meta = {
      description = "Runtime proof for descriptor-first construction of an AOS ZFS mount";
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
        fsopenMountProbe
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
      MODPROBE = "${pkgs.kmod}/sbin/modprobe"
      TRUNCATE = "${pkgs.coreutils}/bin/truncate"
      BASH = "${pkgs.bash}/bin/bash"
      CAT = "${pkgs.coreutils}/bin/cat"
      DD = "${pkgs.coreutils}/bin/dd"
      RM = "${pkgs.coreutils}/bin/rm"
      UNAME = "${pkgs.coreutils}/bin/uname"
      STAT = "${pkgs.coreutils}/bin/stat"
      FINDMNT = "${pkgs.util-linux}/bin/findmnt"
      UMOUNT = "${pkgs.util-linux}/bin/umount"
      JQ = "${pkgs.jq}/bin/jq"
      PROBE = "${idmappedMountProbe}/bin/aos-zfs-idmapped-mount-probe"
      FSOPEN_PROBE = "${fsopenMountProbe}/bin/aos-zfs-fsopen-mount-probe"
      REPORT = "/var/tmp/aos-zfs-platform-proof.json"

      vm.wait_for_unit("multi-user.target", timeout=120)
      vm.succeed(f"{MODPROBE} zfs")
      vm.succeed(f"test -d /sys/module/zfs")
      vm.succeed(f"{TRUNCATE} -s 1G /var/tmp/aos-zfs-platform-proof.pool")
      vm.succeed(
          f"{ZPOOL} create -f -m none -o cachefile=none "
          "aosproof /var/tmp/aos-zfs-platform-proof.pool"
      )
      vm.succeed(
          "mkdir -p /var/tmp/aos-zfs-source /var/tmp/aos-zfs-clone "
          "/var/tmp/aos-zfs-idmap /var/tmp/aos-zfs-fsopen "
          "/var/tmp/aos-zfs-fsopen-early"
      )
      # Establish the descriptor-first platform fact before unrelated storage
      # policy checks so a later failure cannot hide kernel/OpenZFS support.
      vm.succeed(
          f"{ZFS} create -o mountpoint=none -o canmount=off "
          "aosproof/fsopen-early"
      )
      fsopen_early = json.loads(
          vm.succeed(
              f"{FSOPEN_PROBE} aosproof/fsopen-early /var/tmp/aos-zfs-fsopen-early"
          )
      )
      assert fsopen_early["descriptor_attached"] is True, fsopen_early
      assert fsopen_early["zfs_mount_id"] != fsopen_early["underlying_mount_id"], fsopen_early
      assert (
          vm.succeed(f"{FINDMNT} -n -o SOURCE --target /var/tmp/aos-zfs-fsopen-early").strip()
          == "aosproof/fsopen-early"
      )
      vm.succeed(f"{UMOUNT} /var/tmp/aos-zfs-fsopen-early")
      vm.succeed(f"{ZFS} destroy aosproof/fsopen-early")

      vm.succeed(
          f"{ZFS} create -o mountpoint=/var/tmp/aos-zfs-source "
          "-o quota=64M aosproof/source"
      )
      vm.succeed("printf 'immutable snapshot payload\\n' > /var/tmp/aos-zfs-source/payload")

      vm.succeed(f"{ZFS} snapshot aosproof/source@base")
      vm.succeed(f"{ZFS} hold aos-sbx-p0-07 aosproof/source@base")
      holds = vm.succeed(f"{ZFS} holds -H aosproof/source@base")
      assert "aos-sbx-p0-07" in holds, holds
      vm.fail(f"{ZFS} destroy aosproof/source@base")

      vm.succeed(
          f"{ZFS} clone -o mountpoint=/var/tmp/aos-zfs-clone "
          "aosproof/source@base aosproof/clone"
      )
      assert vm.succeed("cat /var/tmp/aos-zfs-clone/payload") == "immutable snapshot payload\n"
      quota = int(vm.succeed(f"{ZFS} get -Hp -o value quota aosproof/source").strip())
      # Reservations charge the parent dataset's logical used space, not the
      # pool's physical allocation counters. Flush earlier dataset activity so
      # the measured delta belongs to this property change.
      vm.succeed(f"{ZPOOL} sync aosproof")
      parent_used_before = int(
          vm.succeed(f"{ZFS} get -Hp -o value used aosproof").strip()
      )
      vm.succeed(f"{ZFS} set reservation=16M aosproof/source")
      vm.succeed(f"{ZPOOL} sync aosproof")
      parent_used_after = int(
          vm.succeed(f"{ZFS} get -Hp -o value used aosproof").strip()
      )
      reservation = int(
          vm.succeed(f"{ZFS} get -Hp -o value reservation aosproof/source").strip()
      )
      assert quota == 64 * 1024 * 1024, quota
      assert reservation == 16 * 1024 * 1024, reservation
      reservation_accounted_bytes = parent_used_after - parent_used_before
      assert reservation_accounted_bytes >= 15 * 1024 * 1024, reservation_accounted_bytes

      quota_status, _, quota_error = vm.execute(
          f"{DD} if=/dev/urandom of=/var/tmp/aos-zfs-source/quota-fill "
          "bs=1M count=80 status=none conv=fsync"
      )
      assert quota_status != 0, quota_status
      assert b"Disk quota exceeded" in quota_error, quota_error
      vm.succeed(f"{ZPOOL} sync aosproof")
      quota_used = int(vm.succeed(f"{ZFS} get -Hp -o value used aosproof/source").strip())
      quota_available = int(
          vm.succeed(f"{ZFS} get -Hp -o value available aosproof/source").strip()
      )
      quota_file_size = int(
          vm.succeed(f"{STAT} -c %s /var/tmp/aos-zfs-source/quota-fill").strip()
      )
      quota_recordsize = int(
          vm.succeed(f"{ZFS} get -Hp -o value recordsize aosproof/source").strip()
      )
      # OpenZFS 2.4.0 dsl_dir_tempreserve_impl intentionally checks current
      # used space without the new allocation (its documented "one free hit")
      # and separately applies quota>>5 inflight slop. Do not invent a
      # recordsize overshoot bound: prove enforcement through EDQUOT, exhausted
      # availability, a partial real write, and a fresh allocation rejection
      # after the pool is synchronized.
      assert quota_available == 0, quota_available
      assert 0 < quota_file_size < 80 * 1024 * 1024, quota_file_size
      assert quota_used >= quota, (quota_used, quota)
      retry_status, _, retry_error = vm.execute(
          f"{DD} if=/dev/urandom of=/var/tmp/aos-zfs-source/quota-fill "
          f"bs={quota_recordsize} count=1 status=none conv=notrunc oflag=append"
      )
      assert retry_status != 0, retry_status
      assert b"Disk quota exceeded" in retry_error, retry_error
      retry_file_size = int(
          vm.succeed(f"{STAT} -c %s /var/tmp/aos-zfs-source/quota-fill").strip()
      )
      assert retry_file_size == quota_file_size, (retry_file_size, quota_file_size)
      vm.succeed(f"{RM} -f /var/tmp/aos-zfs-source/quota-fill")

      # The guest command handler cannot infer an early pipeline member's
      # status. Prove the selected shell reports a failing producer even when
      # its consumer succeeds, then use that exact pipefail boundary for ZFS.
      vm.succeed(
          f"{BASH} -o pipefail -c "
          f"'printf pipeline-probe | {CAT} >/dev/null'"
      )
      pipefail_status, pipefail_output, pipefail_error = vm.execute(
          f"{BASH} -o pipefail -c "
          f"'{{ printf pipeline-probe; exit 23; }} | {CAT} >/dev/null'"
      )
      assert pipefail_status == 23, (
          pipefail_status,
          pipefail_output,
          pipefail_error,
      )
      assert pipefail_output == b"", pipefail_output
      assert pipefail_error == b"", pipefail_error
      vm.succeed(
          f"{BASH} -o pipefail -c '"
          f"{ZFS} send aosproof/source@base | "
          f"{ZFS} receive -o mountpoint=/var/tmp/aos-zfs-received aosproof/received'"
      )
      assert vm.succeed("cat /var/tmp/aos-zfs-received/payload") == "immutable snapshot payload\n"
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
              f"{PROBE} /var/tmp/aos-zfs-source /var/tmp/aos-zfs-idmap "
              "/var/tmp/aos-zfs-source/payload"
          )
      )
      assert idmap == {
          "schema_version": "aos.sandbox.zfs-idmapped-mount/v1",
          "source_uid": 0,
          "source_gid": 0,
          "host_mapped_uid": 100000,
          "host_mapped_gid": 100000,
          "sandbox_mapped_uid": 0,
          "sandbox_mapped_gid": 0,
          "created_source_uid": 0,
          "created_source_gid": 0,
          "idmapped_mount": True,
      }, idmap

      vm.succeed(
          f"{ZFS} create -o mountpoint=none -o canmount=off "
          "aosproof/fsopen"
      )
      fsopen_guid_before = vm.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/fsopen"
      ).strip()
      fsopen_mounted_before = vm.succeed(
          f"{ZFS} get -Hp -o value mounted aosproof/fsopen"
      ).strip()
      assert fsopen_mounted_before == "no", fsopen_mounted_before
      fsopen = json.loads(
          vm.succeed(f"{FSOPEN_PROBE} aosproof/fsopen /var/tmp/aos-zfs-fsopen")
      )
      assert fsopen["schema_version"] == "aos.sandbox.zfs-fsopen-mount/v1", fsopen
      assert fsopen["descriptor_attached"] is True, fsopen
      assert fsopen["zfs_mount_id"] != fsopen["underlying_mount_id"], fsopen
      assert fsopen["root_device"] > 0 and fsopen["root_inode"] > 0, fsopen
      assert vm.succeed(f"{STAT} -f -c %T /var/tmp/aos-zfs-fsopen").strip() == "zfs"
      fsopen_source = vm.succeed(
          f"{FINDMNT} -n -o SOURCE --target /var/tmp/aos-zfs-fsopen"
      ).strip()
      assert fsopen_source == "aosproof/fsopen", fsopen_source
      fsopen_root = vm.succeed(
          f"{FINDMNT} -n -o FSROOT --target /var/tmp/aos-zfs-fsopen"
      ).strip()
      assert fsopen_root == "/", fsopen_root
      fsopen_guid_after = vm.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/fsopen"
      ).strip()
      assert fsopen_guid_after == fsopen_guid_before, (
          fsopen_guid_before,
          fsopen_guid_after,
      )
      fsopen_properties_after = vm.succeed(
          f"{ZFS} get -Hp -o property,value mountpoint,canmount "
          "aosproof/fsopen"
      ).splitlines()
      assert fsopen_properties_after == [
          "mountpoint\tnone",
          "canmount\toff",
      ], fsopen_properties_after

      zfs_versions = vm.succeed(f"{ZFS} version").splitlines()
      assert len(zfs_versions) == 2, zfs_versions
      zfs_version, zfs_kernel_version = [line.strip() for line in zfs_versions]
      assert zfs_version.startswith("zfs-2.4.0"), zfs_versions
      assert zfs_kernel_version.startswith("zfs-kmod-2.4.0"), zfs_versions

      vm.succeed(
          f"{JQ} -n --arg architecture \"$({UNAME} -m)\" "
          f"--arg zfs_version '{zfs_version}' "
          "'{schema_version:\"aos.sandbox.zfs-platform-proof/v1\",evidence_version:1,"
          "architecture:$architecture,zfs_version:$zfs_version,"
          "behaviors:{snapshot:true,hold:true,hold_blocks_destroy:true,clone:true,"
          "quota_property:true,quota_enforced:true,reservation_property:true,"
          "reservation_accounted:true,send_receive:true,received_snapshot_identity:true,"
          "idmapped_mount:true,descriptor_first_zfs_mount:true}}' "
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

      pool_health = vm.succeed(f"{ZPOOL} status -x aosproof").strip()
      assert pool_health == "pool 'aosproof' is healthy", pool_health
      vm.succeed(f"{UMOUNT} /var/tmp/aos-zfs-fsopen")
      vm.succeed(f"{UMOUNT} /var/tmp/aos-zfs-idmap")
      vm.succeed(f"{ZPOOL} destroy aosproof")
      remaining_pools = vm.succeed(f"{ZPOOL} list -H -o name").splitlines()
      assert "aosproof" not in remaining_pools, remaining_pools
      vm.succeed(f"{RM} -f /var/tmp/aos-zfs-platform-proof.pool")
    '';
}
