##! Loads the retained journal-policy declarations during image selection.
{lib, packageModulesAvailable ? false, ...}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/journald.nix];
}
