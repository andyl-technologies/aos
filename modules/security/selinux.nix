##! Selects and verifies the package-owned SELinux policy services.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.security.selinux or {enable = false;};
  policyName = builtins.unsafeDiscardStringContext cfg.policy;
in {
  environment.systemPackages = [pkgs.refpolicy pkgs.policycoreutils];

  config = lib.mkIf cfg.enable {
    # The policy owns its contexts tree; exposing that immutable tree is the
    # system's selected SELinux policy, not a service-manager realization.
    environment.etc."selinux/${policyName}/contexts".source = "${pkgs.refpolicy}/etc/selinux/refpolicy/contexts";

    aos.boot.kernelParams = [
      "selinux=1"
      "security=selinux"
      "enforcing=0"
    ];

    system.checks.selinux = {
      description = "SELinux checks";
      checks = [
        {
          name = "selinuxfs";
          description = "/sys/fs/selinux is present";
          script = ''
            vm.succeed("test -d /sys/fs/selinux")
          '';
        }
        {
          name = "enforce-file";
          description = "SELinux enforce file exists";
          script = ''
            vm.succeed("test -f /sys/fs/selinux/enforce")
          '';
        }
      ];
    };
  };
}
