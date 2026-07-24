# tests/fleet/provisioning-boot.nix — provisioning smoke test.
#
# The minimal end-to-end proof of the boot substrate. It exercises
# metadata transport, repartitioning, config evaluation, and activation in one boot.
#
#   * the initrd authenticating a platform-provided provisioning bundle,
#   * systemd-repart carving the bundle's typed swap + var plan in the
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
      metadata."provisioning.json" = builtins.toJSON {
        schema = "aos.provisioning/v1";
        host_nix.inline = "{}";
        storage.partitions = [
          {
            label = "swap";
            type = "swap";
            size_min_bytes = 1073741824;
            size_max_bytes = 1073741824;
          }
          {
            label = "var";
            type = "var";
            size_min_bytes = 2147483648;
            grow = true;
            format = "ext4";
          }
        ];
      };
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
      node.succeed("test -s /run/aos-metadata/.provisioning-result.json")
      node.succeed("test -s /run/aos-metadata/storage-plan.json")
      node.succeed("test -s /run/aos-metadata/repart.d/50-swap.conf")
      node.succeed("test -s /run/aos-metadata/repart.d/60-var.conf")

      # Identity baked into the image /etc via extendModules.
      hostname = node.succeed("cat /etc/hostname").strip()
      assert hostname == "node", f"hostname is {hostname!r}, expected 'node'"

      hosts = node.succeed("cat /etc/hosts")
      assert "192.168.50.10 node" in hosts, f"/etc/hosts missing fleet entry:\n{hosts}"

      # The .network baked by the identity module (MAC-matched) bound the
      # fleet IP. The guest has no `ip` tool, so read the kernel's local-route
      # trie (/proc/net/fib_trie lists configured addresses) and match the
      # address host-side. net.ifnames=0 is baked, so the NIC is eth0.
      assert "192.168.50.10" in node.succeed(
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

      # The bundle requests a fixed 1 GiB swap partition, deliberately
      # different from the image's baked 2 GiB default. This proves repart
      # consumed authenticated metadata before its first and only disk pass.
      swap_dev = node.succeed("readlink -f /dev/disk/by-partlabel/swap").strip()
      swap_sectors = int(node.succeed(f"cat /sys/class/block/{swap_dev.rsplit('/', 1)[-1]}/size"))
      assert swap_sectors * 512 == 1073741824, (
          f"swap size is {swap_sectors * 512}, expected bundle-defined 1 GiB"
      )

      var_dev = node.succeed("readlink -f /dev/disk/by-partlabel/var").strip()
      var_sectors = int(node.succeed(f"cat /sys/class/block/{var_dev.rsplit('/', 1)[-1]}/size"))
      assert f"{var_dev} /var " in mounts, f"/var not mounted from {var_dev}:\n{mounts}"

      # No failed units.
      failed = node.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units on provisioned boot: {failed!r}"

      # Repart is convergent, not first-boot guarded. A second boot must rerun
      # it without changing either metadata-defined partition.
      node.reboot()
      node.succeed("systemctl is-active multi-user.target")
      node.succeed("systemctl is-active aos-repart.service")
      swap_dev_after = node.succeed("readlink -f /dev/disk/by-partlabel/swap").strip()
      var_dev_after = node.succeed("readlink -f /dev/disk/by-partlabel/var").strip()
      swap_sectors_after = int(
          node.succeed(f"cat /sys/class/block/{swap_dev_after.rsplit('/', 1)[-1]}/size")
      )
      var_sectors_after = int(
          node.succeed(f"cat /sys/class/block/{var_dev_after.rsplit('/', 1)[-1]}/size")
      )
      assert swap_sectors_after == swap_sectors, "swap changed across idempotent repart"
      assert var_sectors_after == var_sectors, "var changed across idempotent repart"
      failed = node.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after provisioned reboot: {failed!r}"
    '';
}
