# Persistent home directories enabled from runtime host.nix.
#
# The image is the stock server-test variant with homes disabled. Metadata
# host.nix enables `aos.homes`, declares an interactive account, and seeds a
# skeleton file through native package evaluation and committed activation. The test then proves the account's home is created
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
        "aos-test-agent".enable = true;

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
      import json

      RUNTIME = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
      PROFILE = "/var/lib/profiles/system"

      def wait_for_activation(machine):
          machine.wait_until_succeeds(
              "systemctl is-active --quiet aos-activate.service", timeout=300
          )
          generation = json.loads(machine.succeed(
              f"{RUNTIME} deployment-current --profile {PROFILE} --committed-during-recovery"
          ))["generation"]
          assert isinstance(generation, int) and generation > 0, generation
          directory = f"{PROFILE}/gen-{generation}"
          marker = json.loads(machine.succeed(f"cat {directory}/native-deployment.json"))
          descriptor = json.loads(machine.succeed(f"cat {directory}/evaluation.json"))
          assert marker["profile_generation"] == generation, marker
          assert descriptor["schema"] == "aos.package.evaluation-input", descriptor
          machine.succeed(f"test -s {PROFILE}/deployment/generations.journal")
          machine.succeed(f"test -s {PROFILE}/deployment/effects.journal")
          machine.wait_for_unit("multi-user.target", timeout=300)


      def diagnostics(machine):
          return machine.succeed(
              "systemctl --failed --no-legend --no-pager; "
              "cat /proc/mounts; "
              "ls -la /var/home /var/roothome /home /root 2>&1; "
              "journalctl -u home.mount -u root.mount -u aos-homes.service "
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

      # The native seed service prepares root's authoring tree on the state volume.
      workstation.succeed("test -d /root/.config/apm/registries.d")

      # A user's edits survive rerunning the native seed service; existing files
      # are retained while missing skeleton files are copied into the home.
      workstation.succeed(
          "systemd-run --wait --quiet --uid=alice --gid=alice "
          "bash -c 'echo \"export EDITED=yes\" >> \"$HOME/.bashrc\"'"
      )
      workstation.succeed("systemctl restart aos-homes.service")
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
