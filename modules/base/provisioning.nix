##! Shares the retained one-time provisioning policy with image evaluation.
{
  lib,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-storage-provisioning-provider/configuration.nix];
}
