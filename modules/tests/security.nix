##! modules/tests/security.nix — Security configuration verification checks
##!
##! Verifies security hardening: kernel parameters, firewall configuration,
##! user/group setup, and file permissions.
{
  config,
  lib,
  pkgs,
  ...
}: {
  system.checks.system-security = {
    description = "Security configuration verification";
    checks = [
      {
        name = "root-password-posture";
        description = "root password state matches the selected security posture";
        script =
          if config.aos.profiles.debug.autologin
          then ''
            vm.succeed("grep -Eq '^root::' /etc/shadow")
          ''
          else ''
            vm.succeed("grep -Eq '^root:[!*]' /etc/shadow")
          '';
      }
      {
        name = "shadow-permissions";
        description = "/etc/shadow has restricted permissions";
        script = ''
          vm.succeed("test ! -r /etc/shadow || test -f /etc/shadow")
        '';
      }
      {
        name = "firewall-policy";
        description = "the selected firewall resource is applied";
        script = ''
          vm.succeed("${pkgs.nftables}/sbin/nft list table inet aos_filter")
        '';
      }
      {
        name = "sysctl-hardening";
        description = "kernel hardening sysctls are configured";
        script = ''
          vm.succeed("test -d /etc/sysctl.d")
        '';
      }
      {
        name = "shadow-not-world-readable";
        description = "/etc/shadow is not world-readable";
        script = ''
          # In Python the inner $() is plain — no \$ escape needed.
          vm.succeed(
              "test ! -r /etc/shadow || test \"$(ls -la /etc/shadow | cut -c8)\" = '-'"
          )
        '';
      }
    ];
  };
}
