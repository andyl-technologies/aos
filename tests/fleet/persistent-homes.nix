# Persistent home directories enabled from runtime host.nix.
#
# The image is the stock server-test variant with homes disabled. Metadata
# host.nix enables `aos.homes`, declares an interactive account, and seeds a
# skeleton file, all through the production aos-eval -> aos-graph-compile ->
# aos-activate transaction. The test then proves the account's home is created
# on the state volume with the right ownership, that data written through
# /home and /root lands on /var, and that both survive a reboot.
{
  pkgs,
  systems,
  ...
}: {
  name = "persistent-homes";
  timeout = 1500;
  systemReadyTimeout = 0;

  machines.workstation = {
    system = systems.server-test;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.apm.desiredPackages = [ "aos-test-agent" ];

        aos.homes.enable = true;
        aos.homes.skel.".bashrc".text = "export AOS_HOMES_SKEL=seeded\n";

        aos.users.groups.alice = { gid = 1000; members = []; };
        aos.users.users.alice = {
          uid = 1000;
          group = "alice";
          shell = "${pkgs.bash}/bin/bash";
          description = "Workstation user";
        };
      }
    '';
  };

  testScript =
    # python
    ''
      def wait_for_activation(machine):
          machine.succeed(
              "timeout --kill-after=2s 300s bash -c '"
              "until test -s /run/aos/manifest.json "
              "&& test -s /run/aos/graph.json "
              "&& test -s /run/aos/activation.json; "
              "do sleep 1; done'",
              timeout=310,
          )
          machine.wait_for_unit("multi-user.target", timeout=300)


      def diagnostics(machine):
          return machine.succeed(
              "systemctl --failed --no-legend --no-pager; "
              "cat /proc/mounts; "
              "ls -la /var/home /var/roothome /home /root 2>&1; "
              "journalctl -u home.mount -u root.mount -u systemd-tmpfiles-setup.service "
              "--no-pager --output=cat 2>&1 | tail -n 40"
          )


      def assert_homes_bound(machine):
          mounts = machine.succeed("cat /proc/mounts")
          assert " /root " in mounts, f"/root is not bound:\n{diagnostics(machine)}"
          assert " /home " in mounts, f"/home is not bound:\n{diagnostics(machine)}"


      wait_for_activation(workstation)
      assert_homes_bound(workstation)

      # The activation transaction rendered the account, its home, and the
      # skeleton copy without a reboot.
      passwd = workstation.succeed("getent passwd alice").strip()
      assert passwd.endswith(":/var/home/alice:${pkgs.bash}/bin/bash"), passwd
      ownership = workstation.succeed("stat -c '%U:%G %a' /home/alice").strip()
      assert ownership == "alice:alice 700", (
          f"/home/alice ownership {ownership!r}:\n{diagnostics(workstation)}"
      )
      skel_owner = workstation.succeed("stat -c %U /home/alice/.bashrc").strip()
      assert skel_owner == "alice", f".bashrc is owned by {skel_owner}"

      # Write through /home as the account and through /root as root; both
      # must land on the state volume.
      workstation.succeed(
          "systemd-run --wait --quiet --uid=alice --gid=alice "
          "bash -c 'echo persisted > \"$HOME/note\"'"
      )
      workstation.succeed("test \"$(cat /var/home/alice/note)\" = persisted")
      workstation.succeed("test \"$(stat -c %U /var/home/alice/note)\" = alice")
      workstation.succeed("echo root-note > /root/note")
      workstation.succeed("test \"$(cat /var/roothome/note)\" = root-note")

      # Root's apm authoring tree is created by tmpfiles on the state volume.
      workstation.succeed("test -d /root/.config/apm/registries.d")

      # A user's edit to a skeleton-seeded file must survive activation
      # reruns of tmpfiles: the copy rule only fires for a missing file.
      workstation.succeed(
          "systemd-run --wait --quiet --uid=alice --gid=alice "
          "bash -c 'echo \"export EDITED=yes\" >> \"$HOME/.bashrc\"'"
      )
      workstation.succeed("systemd-tmpfiles --create /etc/tmpfiles.d/aos-homes.conf")
      workstation.succeed("grep -q EDITED /home/alice/.bashrc")

      workstation.reboot(timeout=600)
      wait_for_activation(workstation)
      assert_homes_bound(workstation)

      workstation.succeed("test \"$(cat /home/alice/note)\" = persisted")
      workstation.succeed("test \"$(cat /root/note)\" = root-note")
      workstation.succeed("grep -q EDITED /home/alice/.bashrc")
      ownership = workstation.succeed("stat -c '%U:%G %a' /home/alice").strip()
      assert ownership == "alice:alice 700", ownership
    '';
}
