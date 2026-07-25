# tests/fleet/provisioning-boot.nix — provisioning smoke test.
#
# The minimal end-to-end proof of the boot substrate. It exercises
# metadata transport, repartitioning, config evaluation, and activation in one boot.
#
#   * the initrd authenticating literal platform-provided host.nix,
#   * restricted evaluation projecting its typed swap + var plan,
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
}: {
  name = "provisioning-boot";
  # Shared image builds plus positive, fallback, multi-device, and fail-closed
  # UEFI boots. No registry or upgrade, so this remains cheaper than
  # install-from-image.
  timeout = 1200;

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
      import re
      import subprocess
      import time
      from pathlib import Path

      # Reaching the agent handshake proves the complete provisioned boot:
      # UEFI -> sd-boot -> UKI -> systemd initrd -> aos-repart (carve swap/var)
      # -> mount-var -> aos-config-seed (empty /etc lower) -> overlays ->
      # switch-root -> stage-2 -> baked aos-test-agent.service answered.
      node.succeed("systemctl is-active multi-user.target")
      node.wait_for_unit("aos-host-config-cache.service", timeout=120)
      if node.succeed(
          "if test -s /run/aos/manifest.json; then echo present; else echo missing; fi"
      ).strip() != "present":
          eval_log = node.succeed(
              "journalctl -u aos-eval.service -u aos-host-config-cache.service "
              "--no-pager --output=cat"
          ).strip()
          raise AssertionError(
              "full host.nix evaluation did not emit a manifest:\n"
              f"{eval_log}"
          )
      node.succeed("test -s /run/aos-metadata/.provisioning-result.json")
      node.succeed("test -s /run/aos-metadata/provisioning-plan.json")
      node.succeed("test -s /run/aos-metadata/repart-targets")
      node.succeed("test -s /var/lib/aos-provisioning/audit.json")
      node.succeed("test -s /var/lib/aos-provisioning/initial-plan.json")
      node.succeed("test -s /var/lib/aos-provisioning/desired/provisioning-plan.json")
      node.succeed("test -s /var/lib/aos-provisioning/desired/repart-targets")
      node.succeed("test -s /var/lib/aos-provisioning/current/host.nix")
      node.succeed(
          "case \"$(cat /var/lib/aos-provisioning/audit.json)\" in "
          "*'\"source\": \"operator\"'*) ;; *) exit 1 ;; esac"
      )
      node.succeed(
          "case \"$(cat /run/aos-metadata/repart.d/*/*.conf)\" in "
          "*SizeMinBytes=1G*) ;; *) exit 1 ;; esac"
      )

      # Identity baked into the image /etc via extendModules.
      hostname = node.succeed("cat /etc/hostname").strip()
      assert hostname == "node", f"hostname is {hostname!r}, expected 'node'"

      hosts = node.succeed("cat /etc/hosts")
      assert "192.168.50.13 node" in hosts, f"/etc/hosts missing fleet entry:\n{hosts}"

      # The .network baked by the identity module (MAC-matched) bound the
      # fleet IP. The guest has no `ip` tool, so read the kernel's local-route
      # trie (/proc/net/fib_trie lists configured addresses) and match the
      # address host-side. net.ifnames=0 is baked, so the NIC is eth0.
      assert "192.168.50.13" in node.succeed(
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
          raise AssertionError(
              f"failed units on provisioned boot: {failed!r}\n"
              f"aos-eval.service journal:\n{eval_log}"
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
      node.succeed(
          "case \"$(cat /run/aos-metadata/repart.d/*/*-var.conf)\" in "
          "*UUID=*) ;; *) exit 1 ;; esac"
      )

      # A second boot must reacquire and fully evaluate host.nix, while the
      # durable marker freezes both host-defined partitions. The restricted
      # storage projection is advisory and repart reports coherence without
      # mutating the committed layout.
      node.reboot()
      node.wait_until_succeeds(
          "systemctl is-active multi-user.target", timeout=120
      )
      node.succeed("test -s /run/aos-metadata/host.nix")
      node.succeed("test -s /run/aos-metadata/.metadata-result.json")
      node.succeed("test -s /run/aos-metadata/.provisioning-result.json")
      node.succeed("test -s /run/aos/manifest.json")
      node.succeed("test \"$(cat /run/aos-metadata/storage-coherence)\" = coherent")
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
      # runtime configuration. Stage 2 restores only the hash-checked input
      # that previously produced a manifest, while storage coherence is
      # explicitly unavailable rather than guessed.
      node.reboot_without_metadata()
      node.wait_until_succeeds(
          "systemctl is-active multi-user.target", timeout=120
      )
      node.succeed("test -s /run/aos-metadata/host.nix")
      node.succeed("test -s /run/aos/manifest.json")
      node.succeed(
          "test \"$(cat /run/aos-metadata/storage-coherence)\" = unavailable"
      )
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
      # that choice both in GPT and in the durable audit record.
      fallback.succeed("systemctl is-active multi-user.target")
      fallback.succeed(
          "test -e /dev/disk/by-partlabel/aos-provenance-fallback-v1"
      )
      fallback.succeed("test -s /var/lib/aos-provisioning/audit.json")
      fallback.succeed(
          "case \"$(cat /var/lib/aos-provisioning/audit.json)\" in "
          "*'\"source\": \"fallback\"'*) ;; *) exit 1 ;; esac"
      )
      fallback.succeed(
          "test -s /var/lib/aos-provisioning/desired/repart-targets"
      )
      fallback_failed = fallback.succeed(
          "systemctl --failed --no-legend"
      ).strip()
      assert not fallback_failed, (
          f"failed units on fallback provisioning boot: {fallback_failed!r}"
      )

      # A committed fallback machine has no host.nix by definition, but it
      # still re-evaluates the schema-default arm and reports coherence.
      fallback.reboot()
      fallback.wait_until_succeeds(
          "systemctl is-active multi-user.target", timeout=120
      )
      fallback.succeed(
          "test \"$(cat /run/aos-metadata/storage-coherence)\" = coherent"
      )

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
      multidisk.succeed(
          "test -s /var/lib/aos-provisioning/desired/repart-targets"
      )

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
