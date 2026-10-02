##! Reuses the Linux package's native command-line contract for image options.
{
  lib,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/kernel/_kernel-interface/module.nix];
}
