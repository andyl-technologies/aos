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
  # One image build + two UEFI boots + repart carve/idempotency assertions.
  # No registry or upgrade, so this remains cheaper than install-from-image.
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
  };

  testScript =
    # python
    ''
      import re

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
      assert "192.168.50.11 node" in hosts, f"/etc/hosts missing fleet entry:\n{hosts}"

      # The .network baked by the identity module (MAC-matched) bound the
      # fleet IP. The guest has no `ip` tool, so read the kernel's local-route
      # trie (/proc/net/fib_trie lists configured addresses) and match the
      # address host-side. net.ifnames=0 is baked, so the NIC is eth0.
      assert "192.168.50.11" in node.succeed(
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
    '';
}
