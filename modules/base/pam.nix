##! Projects native package-owned PAM configuration into image bootstrap data.
{
  config,
  lib,
  pkgs,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/session-environment.nix];

  config = {
    environment.systemPackages = [pkgs.linux-pam];
    environment.etc = config.aos.pam.files;
  };
}
