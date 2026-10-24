##! Loads the canonical package-owned Linux audit policy during image selection.
##!
##! The audit package owns daemon/rule services, file effects and finite bounds.
{
  lib,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/security/_audit/policy.nix];
}
