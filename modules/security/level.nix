##! Imports the retained package declaration while selecting image packages.
{packageModulesAvailable ? false, ...}: {
  imports =
    if packageModulesAvailable
    then []
    else [../../pkgs/system/_aos-host-policy/security-level.nix];
}
