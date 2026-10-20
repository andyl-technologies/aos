##! Selects the canonical native observational-facts declaration for image setup.
{
  lib,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/tools/_aos-metadata-provider/facts/module.nix];
}
