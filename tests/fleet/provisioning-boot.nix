# tests/fleet/provisioning-boot.nix — provisioning smoke test.
#
# The minimal end-to-end proof of the boot substrate. It exercises
# metadata transport, repartitioning, config evaluation, and activation in one boot.
#
#   * the initrd authenticating literal platform-provided host.nix,
#   * complete initrd evaluation projecting its typed swap + var plan,
#   * systemd-repart carving that plan in the
#     trailing free space of the grown per-run image disk,
#   * `aos-config-seed` scaffolding the empty per-gen /etc lower,
#   * per-VM identity (hostname, /etc/hosts, the eth0 .network, the guest-agent
#     unit) baked into the image /etc via `extendModules`,
#
# and asserts the machine reaches multi-user.target with the identity applied,
# the read-only erofs root mounted, and /var carved by repart. It is the cheap
# gate that must pass before the heavier image-boot install tests
# (install-from-image / secure-boot / measured-boot).
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  # The provisioning transaction derives its deterministic repart seed from
  # each target's GPT UUID. Keep only the primary GPT in the store fixture;
  # the driver expands it to the declared disk size and systemd-repart writes
  # the canonical backup table while applying the first partition plan. Each
  # extra disk gets its own GUID so no two targets share a repart seed.
  mkEmptyDiskGpt = name: diskGuid:
    pkgs.runCommand "aos-provisioning-empty-${name}-gpt" {
      buildDeps = [pkgs.gptfdisk];
    } ''
        work_disk="$TMPDIR/empty-disk.img"
        truncate -s 4096M "$work_disk"
        ${pkgs.gptfdisk}/sbin/sgdisk --clear \
          --disk-guid=${diskGuid} \
          "$work_disk"
      dd if="$work_disk" of="$out/disk.gpt" bs=512 count=34 status=none
    '';
  emptyDataDiskGpt = mkEmptyDiskGpt "data-disk" "11111111-2222-4333-8444-555555555556";
  emptyMirrorDiskGpt = mkEmptyDiskGpt "mirror-disk" "11111111-2222-4333-8444-555555555557";
  emptyMirrorDisk2Gpt = mkEmptyDiskGpt "mirror-disk-2" "11111111-2222-4333-8444-555555555558";
in {
  name = "provisioning-boot";
  # Shared image builds plus positive, fallback, multi-device, mirrored, and
  # fail-closed UEFI boots. No registry or upgrade, so this remains cheaper
  # than install-from-image.
  timeout = 1800;

  machines = {
    node = {
      system = systems.server-test;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions = {
            swap = {
              sizeMin = "1G";
              sizeMax = "1G";
            };
            var.sizeMin = "2G";
          };
        }
      '';
    };
    fallback = {
      system = systems.server-test;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
    };
    multidisk = {
      system = systems.server-test;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      extraDisks = [
        {
          serial = "aos-data";
          sizeMiB = 4096;
          source = "${emptyDataDiskGpt}/disk.gpt";
        }
      ];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.data = {
            device = "/dev/disk/by-id/virtio-aos-data";
            label = "data";
            sizeMin = "1G";
            sizeMax = "1G";
            format = "ext4";
          };
        }
      '';
    };
    # The system-state volume and a data volume each live on a two-member
    # MD mirror declared entirely from host.nix. The root disk contributes
    # the fixed `var` member; the second member and both data members sit on
    # two extra virtio disks. The data mirror is xfs, so the initrd formats
    # a non-default filesystem and stage 2 mounts it by label.
    mirrored = {
      system = systems.server-test;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      extraDisks = [
        {
          serial = "aos-mirror";
          sizeMiB = 4096;
          source = "${emptyMirrorDiskGpt}/disk.gpt";
        }
        {
          serial = "aos-mirror-2";
          sizeMiB = 4096;
          source = "${emptyMirrorDisk2Gpt}/disk.gpt";
        }
      ];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage = {
            partitions = {
              var = {
                sizeMin = "2G";
                sizeMax = "2G";
                grow = false;
              };
              var-mirror = {
                device = "/dev/disk/by-id/virtio-aos-mirror";
                sizeMin = "2G";
                sizeMax = "2G";
                priority = 9000;
              };
              data-a = {
                device = "/dev/disk/by-id/virtio-aos-mirror";
                sizeMin = "1G";
                sizeMax = "1G";
                priority = 1000;
              };
              data-b = {
                device = "/dev/disk/by-id/virtio-aos-mirror-2";
                sizeMin = "1G";
                sizeMax = "1G";
              };
            };
            arrays = {
              var = {
                level = "raid1";
                members = [ "var" "var-mirror" ];
              };
              data = {
                level = "raid1";
                members = [ "data-a" "data-b" ];
                format = "xfs";
              };
            };
          };
          aos.filesystems.volumes.data.mountPoint = "/srv/data";
        }
      '';
    };
    invalid = {
      system = systems.server-test;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      expectAgent = false;
      # A legacy-style JSON provisioning bundle is merely invalid host.nix;
      # there is no parallel JSON configuration path or fallback on failure.
      metadata."host.nix" = ''{"storage":{"partitions":{}}}'';
    };
    signed_invalid = {
      system = systems.server-test;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      expectAgent = false;
      extraModules = [
        {
          aos.apm.configKeys.ops = [
            "ops:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIJiuCf/fX/rsn5ODyT5ebEVtabAmZceKi2aD+cBWjWKL"
          ];
          aos.config.evalAtBoot.trust = "signed";
        }
      ];
      metadata."host.nix" = ''
        { aos.provisioning.storage.partitions.var.sizeMin = "2G"; }
      '';
    };
  };

  testScript =
    # python
    ''
      import json
      import re
      import subprocess
      import time
      from pathlib import Path

      # Reaching the agent handshake proves the complete provisioned boot:
      # UEFI -> sd-boot -> UKI -> systemd initrd -> aos-repart (carve swap/var)
      # -> mount-var -> aos-config-seed (empty /etc lower) -> overlays ->
      # switch-root -> stage-2 -> baked aos-test-agent.service answered.
      node.succeed("systemctl is-active multi-user.target")
      node.wait_for_unit("aos-ability-host-receiver.service", timeout=120)
      if node.succeed(
          "if test -s /run/aos/manifest.json; then echo present; else echo missing; fi"
      ).strip() != "present":
          eval_log = node.succeed(
              "journalctl -u aos-eval.service -u aos-ability-host-receiver.service "
              "--no-pager --output=cat"
          ).strip()
          raise AssertionError(
              "full host.nix evaluation did not emit a manifest:\n"
              f"{eval_log}"
          )
      node.succeed("test ! -e /run/aos-metadata")

      checkpoint = json.loads(
          node.succeed("cat /run/aos/ability-stage-handoff/initrd.json")
      )
      assert checkpoint["status"] == "ownership-released", checkpoint
      boot_id = node.succeed("cat /proc/sys/kernel/random/boot_id").strip()
      boot_token = boot_id.replace("-", "")
      transaction = f"initrd-{boot_token}"
      journal_path = (
          "/var/lib/profiles/image/ability-stage-transactions/initrd/"
          f"{transaction}/execution.journal"
      )
      journal_hex = node.succeed(
          f"od -An -v -tx1 {journal_path}"
      ).replace(" ", "").replace("\n", "")
      for marker in (
          '"key":"authorize-offline-provisioning"',
          '"output":"network-bootstrap"',
          '"key":"apply-network-bootstrap-provisioning"',
          '"key":"commit-authorized-input-provisioning"',
          '"output":"artifact-resource"',
          '"name":"aos.artifact.content-addressed-object"',
      ):
          assert marker.encode().hex() in journal_hex, marker

      # Identity baked into the image /etc via extendModules.
      hostname = node.succeed("cat /etc/hostname").strip()
      assert hostname == "node", f"hostname is {hostname!r}, expected 'node'"

      # Fleet addresses are assigned in machine-name order, so read the
      # driver's assignment instead of hardcoding it.
      hosts = node.succeed("cat /etc/hosts")
      assert f"{node.ip} node" in hosts, f"/etc/hosts missing fleet entry:\n{hosts}"

      # The .network baked by the identity module (MAC-matched) bound the
      # fleet IP. The guest has no `ip` tool, so read the kernel's local-route
      # trie (/proc/net/fib_trie lists configured addresses) and match the
      # address host-side. net.ifnames=0 is baked, so the NIC is eth0.
      assert node.ip in node.succeed(
          "cat /proc/net/fib_trie"
      ), "the baked fleet address was not assigned to any interface"

      # The read-only erofs root — the immutable base — is mounted ro.
      mounts = node.succeed("cat /proc/mounts")
      assert re.search(r"^\S+ / erofs ro\b", mounts, re.M), (
          f"root not mounted as read-only erofs:\n{mounts}"
      )

      # systemd-repart carved swap + var in the free space after root-a.
      # /var is mounted from the repart partition. (A
      # reserved root-b slot is future A/B work — see modules/services/repart.nix.)
      for label in ("root-a", "swap", "var"):
          node.succeed(f"test -e /dev/disk/by-partlabel/{label}")
      root_dev = node.succeed(
          "readlink -f /dev/disk/by-partlabel/root-a"
      ).strip()
      root_type = node.succeed(
          f"${pkgs.util-linux}/bin/lsblk -no PARTTYPE {root_dev}"
      ).strip().lower()
      assert root_type == "4f68bce3-e8cd-4db1-96e7-fbcaf984b709", (
          f"root-a has non-DPS or wrong-architecture type {root_type!r}"
      )

      # host.nix requests a fixed 1 GiB swap partition, deliberately
      # different from the image's baked 2 GiB default. This proves repart
      # consumed authenticated metadata before its first and only disk pass.
      swap_dev = node.succeed("readlink -f /dev/disk/by-partlabel/swap").strip()
      swap_sectors = int(node.succeed(f"cat /sys/class/block/{swap_dev.rsplit('/', 1)[-1]}/size"))
      assert swap_sectors * 512 == 1073741824, (
          f"swap size is {swap_sectors * 512}, expected host-defined 1 GiB"
      )

      var_dev = node.succeed("readlink -f /dev/disk/by-partlabel/var").strip()
      var_sectors = int(node.succeed(f"cat /sys/class/block/{var_dev.rsplit('/', 1)[-1]}/size"))
      assert f"{var_dev} /var " in mounts, f"/var not mounted from {var_dev}:\n{mounts}"

      # No failed units.
      failed = node.succeed("systemctl --failed --no-legend").strip()
      if failed:
          eval_log = node.succeed(
              "journalctl -u aos-eval.service --no-pager --output=cat"
          ).strip()
          commit_log = node.succeed(
              "journalctl -u aos-image-boot-commit.service --no-pager --output=cat"
          ).strip()
          raise AssertionError(
              f"failed units on provisioned boot: {failed!r}\n"
              f"aos-eval.service journal:\n{eval_log}\n"
              f"aos-image-boot-commit.service journal:\n{commit_log}"
          )

      node.succeed("test -e /dev/disk/by-partlabel/aos-provenance-operator-v1")
      marker_dev = node.succeed(
          "readlink -f /dev/disk/by-partlabel/aos-provenance-operator-v1"
      ).strip()
      marker_uuid = node.succeed(
          f"${pkgs.util-linux}/bin/lsblk -ndo PARTUUID {marker_dev}"
      ).strip()
      var_uuid = node.succeed(
          f"${pkgs.util-linux}/bin/lsblk -ndo PARTUUID {var_dev}"
      ).strip()
      assert marker_uuid, "provisioning marker has no AOS-generated UUID"
      assert var_uuid, "omitted var UUID was not materialized by AOS"

      # A second boot must reacquire and fully evaluate host.nix, while the
      # durable marker freezes both host-defined partitions. The restricted
      # typed storage observation leaves the committed layout unchanged.
      node.reboot()
      node.wait_until_succeeds(
          "systemctl is-active multi-user.target", timeout=120
      )
      node.succeed("test ! -e /run/aos-metadata")
      node.succeed("test -s /run/aos/manifest.json")
      marker_dev_after = node.succeed(
          "readlink -f /dev/disk/by-partlabel/aos-provenance-operator-v1"
      ).strip()
      marker_uuid_after = node.succeed(
          f"${pkgs.util-linux}/bin/lsblk -ndo PARTUUID {marker_dev_after}"
      ).strip()
      var_uuid_after = node.succeed(
          f"${pkgs.util-linux}/bin/lsblk -ndo PARTUUID {var_dev}"
      ).strip()
      assert marker_uuid_after == marker_uuid, "marker UUID changed across reboot"
      assert var_uuid_after == var_uuid, "derived var UUID changed across reboot"
      swap_dev_after = node.succeed("readlink -f /dev/disk/by-partlabel/swap").strip()
      var_dev_after = node.succeed("readlink -f /dev/disk/by-partlabel/var").strip()
      swap_sectors_after = int(
          node.succeed(f"cat /sys/class/block/{swap_dev_after.rsplit('/', 1)[-1]}/size")
      )
      var_sectors_after = int(
          node.succeed(f"cat /sys/class/block/{var_dev_after.rsplit('/', 1)[-1]}/size")
      )
      assert swap_sectors_after == swap_sectors, "swap changed after provisioning commit"
      assert var_sectors_after == var_sectors, "var changed after provisioning commit"
      failed = node.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after provisioned reboot: {failed!r}"

      # Detaching metadata after commit must not reopen disk mutation or lose
      # runtime configuration. Stage 2 restores only the content-addressed
      # input retained by the checked initrd stage.
      node.reboot_without_metadata()
      node.wait_until_succeeds(
          "systemctl is-active multi-user.target", timeout=120
      )
      node.succeed("test ! -e /run/aos-metadata")
      node.succeed("test -s /run/aos/manifest.json")
      swap_dev_outage = node.succeed(
          "readlink -f /dev/disk/by-partlabel/swap"
      ).strip()
      swap_sectors_outage = int(
          node.succeed(
              f"cat /sys/class/block/{swap_dev_outage.rsplit('/', 1)[-1]}/size"
          )
      )
      assert swap_sectors_outage == swap_sectors, (
          "metadata outage changed committed swap"
      )

      # A host with no operator input takes the schema-default arm and records
      # that choice in the durable GPT marker.
      fallback.succeed("systemctl is-active multi-user.target")
      fallback.succeed(
          "test -e /dev/disk/by-partlabel/aos-provenance-fallback-v1"
      )
      fallback.succeed("test ! -e /run/aos-metadata")
      fallback_failed = fallback.succeed(
          "systemctl --failed --no-legend"
      ).strip()
      assert not fallback_failed, (
          f"failed units on fallback provisioning boot: {fallback_failed!r}"
      )

      # A committed fallback machine has no host.nix by definition, but it
      # still re-evaluates the schema-default arm from retained stage evidence.
      fallback.reboot()
      fallback.wait_until_succeeds(
          "systemctl is-active multi-user.target", timeout=120
      )
      fallback.succeed("test -s /run/aos/manifest.json")

      # The real renderer and repart implementation handle a second stable
      # device in the same first-boot transaction. The whole-machine marker
      # remains on the root disk while the data partition lands on the
      # virtio serial-backed disk.
      multidisk.succeed("systemctl is-active multi-user.target")
      multidisk.succeed(
          "test -e /dev/disk/by-partlabel/aos-provenance-operator-v1"
      )
      data_dev = multidisk.succeed(
          "readlink -f /dev/disk/by-partlabel/data"
      ).strip()
      data_parent = multidisk.succeed(
          f"${pkgs.util-linux}/bin/lsblk -ndo PKNAME {data_dev}"
      ).strip()
      stable_data_parent = multidisk.succeed(
          "readlink -f /dev/disk/by-id/virtio-aos-data"
      ).strip().rsplit("/", 1)[-1]
      assert data_parent == stable_data_parent, (
          f"data partition parent {data_parent!r} is not extra disk "
          f"{stable_data_parent!r}"
      )
      multidisk.succeed("test ! -e /run/aos-metadata")

      # An additional desired partition on the extra disk produces pending
      # repart work without mutating it, exercising the live divergence
      # predicate against a layout with enough free space for a valid plan.
      multidisk.succeed(
          "mkdir -p /run/aos-divergent && "
          "printf '%s\\n' '[Partition]' "
          "'Type=11111111-2222-4333-8444-555555555555' "
          "'Label=divergence-probe' 'SizeMinBytes=512M' 'SizeMaxBytes=512M' "
          "> /run/aos-divergent/10-probe.conf"
      )
      multidisk.succeed(
          f"result=$(${pkgs.systemd}/bin/systemd-repart "
          f"--definitions=/run/aos-divergent --dry-run=yes --empty=allow "
          f"--json=short /dev/{stable_data_parent}); "
          f"printf '%s\\n' \"$result\" | ${pkgs.jq}/bin/jq -e "
          f"'any(.[]; .activity != \"unchanged\")' >/dev/null"
      )

      # Both mirrors were created in the first-boot transaction: the system
      # state runs on /dev/md/var, the data volume on /dev/md/data mounted by
      # its filesystem label, and every member is a linux-raid partition. The
      # provenance marker committed only after the arrays existed.
      MDADM = "${pkgs.mdadm}/sbin/mdadm"
      LSBLK = "${pkgs.util-linux}/bin/lsblk"
      LINUX_RAID = "a19d880f-05fc-4d3b-a006-743f0f84911e"

      def storage_diagnostics():
          # Collected before an assertion fails so a broken layout explains
          # itself: unit state, kernel md state, udev symlinks, and the
          # journal lines of the units that assemble and mount the volumes.
          return mirrored.succeed(
              "systemctl --failed --no-legend; echo ---; cat /proc/mdstat;"
              " echo ---; ls -l /dev/md /dev/disk/by-label 2>&1; echo ---;"
              " journalctl -b --no-pager -o cat -u srv-data.mount"
              " -u 'dev-disk-by\\x2dlabel-data.device' -u aos-storage-topology"
              " 2>&1 | tail -40"
          )

      def assert_mirrored_layout(label):
          mirrored.succeed("systemctl is-active multi-user.target")
          mounts = mirrored.succeed("cat /proc/mounts")
          md_var = mirrored.succeed("readlink -f /dev/md/var").strip()
          md_data = mirrored.succeed("readlink -f /dev/md/data").strip()
          assert f"{md_var} /var ext4" in mounts, (
              f"{label}: /var not on md/var:\n{mounts}\n{storage_diagnostics()}"
          )
          assert f"{md_data} /srv/data xfs" in mounts, (
              f"{label}: /srv/data not on md/data as xfs:\n{mounts}\n{storage_diagnostics()}"
          )
          for name, level, members in (("var", "raid1", 2), ("data", "raid1", 2)):
              detail = mirrored.succeed(f"{MDADM} --detail /dev/md/{name}")
              assert f"Raid Level : {level}" in detail, detail
              assert f"Raid Devices : {members}" in detail, detail
              assert f"Name : aos:{name}" in detail, detail
          failed = mirrored.succeed("systemctl --failed --no-legend").strip()
          assert not failed, f"{label}: failed units: {failed!r}"

      assert_mirrored_layout("first boot")
      mirrored.succeed("test -e /dev/disk/by-partlabel/aos-provenance-operator-v1")
      mirrored.succeed("test ! -e /dev/disk/by-partlabel/aos-provisioning-pending-v1")
      for label in ("var", "var-mirror", "data-a", "data-b"):
          member = mirrored.succeed(f"readlink -f /dev/disk/by-partlabel/{label}").strip()
          member_type = mirrored.succeed(f"{LSBLK} -no PARTTYPE {member}").strip().lower()
          assert member_type == LINUX_RAID, f"{label} has type {member_type!r}"
      topology_log = mirrored.succeed(
          "journalctl -b -u aos-storage-topology.service --no-pager --output=cat"
      )
      assert "creating raid1 array var" in topology_log, topology_log
      assert "creating raid1 array data" in topology_log, topology_log
      assert "committed aos-provenance-operator-v1" in topology_log, topology_log
      mirrored.succeed("test -s /var/lib/aos-provisioning/desired/storage-arrays")
      volumes = mirrored.succeed("cat /run/aos-metadata/storage-volumes")
      assert "data\tarray\t/dev/md/data\tdata\tnone\txfs" in volumes, volumes
      assert "var\tarray\t/dev/md/var\tvar\tnone\text4" in volumes, volumes
      mirrored.succeed("echo probe > /srv/data/probe && sync")

      # Later boots assemble the committed arrays from their superblocks
      # whether or not the plan is available, and the plan-backed boot reports
      # the arrays as coherent.
      mirrored.reboot()
      mirrored.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)
      assert_mirrored_layout("reboot")
      mirrored.succeed("test \"$(cat /run/aos-metadata/storage-coherence)\" = coherent")
      mirrored.succeed("test \"$(cat /srv/data/probe)\" = probe")
      topology_log = mirrored.succeed(
          "journalctl -b -u aos-storage-topology.service --no-pager --output=cat"
      )
      assert "creating" not in topology_log, topology_log
      assert "array var is active" in topology_log, topology_log

      mirrored.reboot_without_metadata()
      mirrored.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)
      assert_mirrored_layout("metadata outage")
      mirrored.succeed("test \"$(cat /run/aos-metadata/storage-coherence)\" = unavailable")
      mirrored.succeed("test \"$(cat /srv/data/probe)\" = probe")

      # Present but malformed host.nix fails before GPT mutation. This machine
      # intentionally never reaches the guest agent, so inspect its serial log
      # and writable disk copy from the host-side driver.
      invalid_log = Path(invalid.serial_log_path)
      deadline = time.monotonic() + 120
      invalid_text = ""
      while time.monotonic() < deadline:
          if invalid_log.exists():
              invalid_text = invalid_log.read_text(errors="replace")
              if (
                  "restricted provisioning evaluation failed" in invalid_text
                  or "erofs (device" in invalid_text
              ):
                  break
          time.sleep(1)
      assert "erofs (device" in invalid_text, (
          "JSON provisioning input did not reach a settled initrd failure"
      )
      assert "invalid login:" not in invalid_text, (
          "JSON provisioning input unexpectedly reached the stage-2 system"
      )
      invalid_gpt = subprocess.run(
          ["sgdisk", "-p", invalid.disk_copy],
          check=True,
          text=True,
          capture_output=True,
      ).stdout
      assert "aos-provenance" not in invalid_gpt
      assert "aos-provisioning" not in invalid_gpt
      assert re.search(r"\\bvar\\b", invalid_gpt) is None

      signed_log = Path(signed_invalid.serial_log_path)
      deadline = time.monotonic() + 120
      signed_text = ""
      while time.monotonic() < deadline:
          if signed_log.exists():
              signed_text = signed_log.read_text(errors="replace")
              if (
                  "authorizing signed host.nix" in signed_text
                  or "erofs (device" in signed_text
              ):
                  break
          time.sleep(1)
      assert "erofs (device" in signed_text, (
          "unsigned signed-policy input did not reach a settled initrd failure"
      )
      assert "signed_invalid login:" not in signed_text, (
          "unsigned signed-policy input unexpectedly reached the stage-2 system"
      )
      signed_gpt = subprocess.run(
          ["sgdisk", "-p", signed_invalid.disk_copy],
          check=True,
          text=True,
          capture_output=True,
      ).stdout
      assert "aos-provenance" not in signed_gpt
      assert "aos-provisioning" not in signed_gpt
      assert re.search(r"\\bvar\\b", signed_gpt) is None

      # A crash-observable pending marker refuses automatic replay. Relabel the
      # committed marker, reboot, and require the initrd diagnostic with no
      # stage-2 agent.
      root_disk = node.succeed(
          f"${pkgs.util-linux}/bin/lsblk -ndo PKNAME {root_dev}"
      ).strip()
      marker_number = node.succeed(
          f"cat /sys/class/block/{marker_dev.rsplit('/', 1)[-1]}/partition"
      ).strip()
      node.succeed(
          f"${pkgs.util-linux}/sbin/sfdisk --part-label /dev/{root_disk} "
          f"{marker_number} aos-provisioning-pending-v1"
      )
      node.reboot_expect_rejected(
          settle=30,
          markers=["pending provisioning marker found"],
      )
    '';
}
