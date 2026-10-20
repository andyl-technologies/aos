##! lib/testing/homes.nix — Persistent home directories with `aos.homes` enabled.
##!
##! modules/base/homes.nix contributes its own check group to every system; on
##! the production server it can only cover the always-on `/root` bind. This
##! check enables homes on the VM-harness server variant with an interactive
##! account and a skeleton file, runs the module's enabled-mode checks, and
##! then logs in over SSH to prove the account lands in its persistent home.
{
  lib,
  pkgs,
  mkSystem,
  testing,
}: let
  homesSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {
        # Same harness posture as the default VM checks: the Firecracker
        # harness boots an ext4 root without dm-verity.
        aos.filesystems.rootFsType = lib.mkForce "ext4";
        aos.security.verity.enable = lib.mkForce false;

        aos.homes.enable = true;
        aos.homes.skel.".bashrc".text = ''
          # Seeded from /etc/skel by modules/base/homes.nix.
          export AOS_HOMES_SKEL=seeded
        '';

        aos.users.users.alice = {
          uid = 1000;
          group = "users";
          shell = "${pkgs.bash}/bin/bash";
          description = "Persistent home test account";
        };
      }
    ];
    systemName = "server-homes";
  };

  moduleChecks = homesSystem.config.system.checks.homes.checks;
in
  testing.mkVMTest {
    name = "homes-enabled";
    system = homesSystem;
    groupName = "homes-enabled";
    checks = moduleChecks;
    timeout = 300;
    testScript = ''
      import textwrap

      # Log in as the interactive account over SSH. sshd resolves the home
      # from /etc/passwd, so a working session proves the bind mount, the
      # native home preparation, and the skeleton copy all line up.
      ssh_output = vm.succeed(
          textwrap.dedent(r"""
              set -e
              ${pkgs.openssh}/bin/ssh-keygen -t ed25519 -N "" -f /tmp/aos-homes-key -q
              cat /tmp/aos-homes-key.pub > /etc/ssh/authorized_keys/alice
              chmod 0644 /etc/ssh/authorized_keys/alice
              systemctl is-active --quiet sshd || systemctl start sshd
              ${pkgs.openssh}/bin/ssh -i /tmp/aos-homes-key \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o BatchMode=yes \
                -o LogLevel=ERROR \
                alice@127.0.0.1 'echo "home=$HOME"; touch "$HOME/from-ssh"; . "$HOME/.bashrc"; echo "skel=$AOS_HOMES_SKEL"'
          """).strip()
      )
      assert "home=/var/home/alice" in ssh_output, ssh_output
      assert "skel=seeded" in ssh_output, ssh_output

      # The session wrote through /home onto the state volume as the account.
      owner = vm.succeed("stat -c %U /var/home/alice/from-ssh").strip()
      assert owner == "alice", f"from-ssh is owned by {owner}"
    '';
  }
