##! modules/tests/services.nix — Core services verification checks
##!
##! Verifies provider-neutral configuration published for core services.
{
  config,
  lib,
  ...
}: {
  system.checks.system-services = {
    description = "Core service configuration verification";
    checks = [
      {
        name = "sshd-config";
        description = "sshd configuration file is present";
        script = ''
          vm.succeed("test -f /etc/ssh/sshd_config")
        '';
      }
      {
        name = "chrony-config";
        description = "chrony configuration file is present";
        script = ''
          vm.succeed("test -f /etc/chrony.conf")
        '';
      }
    ];
  };
}
