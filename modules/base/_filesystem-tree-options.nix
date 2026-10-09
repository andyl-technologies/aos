##! Bootstraps retained tree declarations before package selection.
{
  lib,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/boot/_aos-configuration-lower/trees.nix];
}
