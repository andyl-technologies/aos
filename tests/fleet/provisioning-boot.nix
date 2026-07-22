# tests/fleet/provisioning-boot.nix — RFC-0011 provisioning smoke test.
#
# The minimal end-to-end proof of the RFC-0011 boot substrate. It exercises
# metadata transport, repartitioning, config evaluation, and activation in one boot.
#
#   * systemd-repart carving swap + var in the trailing free space of the
#     grown per-run image disk,
#   * `aos-config-seed` scaffolding the empty per-gen /etc lower,
#   * per-VM identity (hostname, /etc/hosts, the eth0 .network, the guest-agent
#     unit) baked into the image /etc via `extendModules` (no metadata channel),
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
  # One image build + one UEFI boot + repart carve + assertions. No registry,
  # no upgrade, no reboot — far cheaper than install-from-image.
  timeout = 1200;

  machines = {
    node = {
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

      # Reaching the agent handshake already proves the whole new-path boot:
      # UEFI -> sd-boot -> UKI -> systemd initrd -> aos-repart (carve swap/var)
      # -> mount-var -> aos-config-seed (empty /etc lower) -> overlays ->
      # switch-root -> stage-2 -> baked aos-test-agent.service answered.
      node.succeed("systemctl is-active multi-user.target")

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

      # systemd-repart carved swap + var in the free space after root-a; no
      # ignition-disks ran. /var is mounted from the repart partition. (A
      # reserved root-b slot is future A/B work — see modules/services/repart.nix.)
      for label in ("root-a", "swap", "var"):
          node.succeed(f"test -e /dev/disk/by-partlabel/{label}")

      var_dev = node.succeed("readlink -f /dev/disk/by-partlabel/var").strip()
      assert f"{var_dev} /var " in mounts, f"/var not mounted from {var_dev}:\n{mounts}"

      # No ignition provisioning unit is loaded/active on the new path. A
      # stray `not-found` ordering reference (a stage-2 unit ordering after the
      # stage-1 files backend by its old name) is harmless — the unit does not
      # exist — so flag only units systemd actually loaded.
      units = node.succeed("systemctl list-units --all --no-legend || true")
      loaded_ignition = [
          line
          for line in units.splitlines()
          if "ignition" in line.lower() and "not-found" not in line
      ]
      assert not loaded_ignition, (
          "a loaded ignition unit is present on the new path:\n"
          + "\n".join(loaded_ignition)
      )

      # No failed units.
      failed = node.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units on new-path boot: {failed!r}"
    '';
}
