##! Selects sudo and verifies its package-owned system integration.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.security.sudo;
  wheelMembers = config.aos.users.groups.wheel.members;
in {
  environment.systemPackages = [pkgs.sudo pkgs.util-linux];

  system.checks.sudo = lib.mkIf cfg.enable {
    description = "sudo policy and privilege checks";
    checks =
      [
        {
          name = "sudo-policy";
          description = "sudoers and PAM configuration are valid";
          script = ''
            vm.succeed("${pkgs.sudo}/sbin/visudo -cf /etc/sudoers")
            vm.succeed("grep -q pam_unix.so /etc/pam.d/sudo")
          '';
        }
        {
          name = "sudo-wrapper";
          description = "sudo is materialized as a root-owned setuid wrapper";
          script = ''
            vm.wait_until_succeeds("test -u /run/wrappers/bin/sudo", timeout=30)
            vm.succeed("test $(stat -c %u:%g /run/wrappers/bin/sudo) = 0:0")
            vm.succeed("sudo -n true")
          '';
        }
        {
          name = "sudo-unauthorized";
          description = "a user outside wheel cannot run sudo";
          script = ''
            vm.fail("setpriv --reuid=65534 --regid=65534 --clear-groups sudo -n true")
          '';
        }
      ]
      ++ lib.optionals (!cfg.wheelNeedsPassword && wheelMembers != []) [
        (let
          userName = builtins.head wheelMembers;
          user = config.aos.users.users.${userName};
          group = config.aos.users.groups.${user.group};
        in {
          name = "sudo-wheel-authorized";
          description = "a configured wheel member can run an authorized command";
          script = ''
            vm.succeed(
                "setpriv --reuid=${toString user.uid} --regid=${toString group.gid} "
                "--groups=${toString config.aos.users.groups.wheel.gid} "
                "sudo -n id -u | grep -Fx 0"
            )
          '';
        })
      ];
  };
}
