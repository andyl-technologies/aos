##! Selects package-owned Linux audit configuration and services.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.security.audit;
in {
  config = lib.mkMerge [
    {environment.systemPackages = [pkgs.audit];}

    (lib.mkIf cfg.enable {
      # Syscall-level audit rules are accepted only when auditing is enabled on
      # the kernel command line, even when CONFIG_AUDITSYSCALL is built in.
      aos.boot.kernelParams = ["audit=1"];

      system.checks.audit = {
        description = "Audit policy checks";
        checks = [
          {
            name = "audit-rules";
            description = "Audit rules file exists";
            script = ''
              vm.succeed("test -f /etc/audit/audit.rules")
            '';
          }
        ];
      };
    })
  ];
}
