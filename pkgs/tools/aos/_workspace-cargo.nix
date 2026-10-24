##! Shared source and patched registry vendor for independent sandbox roles.
##!
##! The shared package-set vendor enforces the canonical registry patch recipe.
##! Only source inputs are shared; role compiler artifacts stay independent.
{
  lib,
  aosWorkspaceVendor,
}: let
  src = import ./_workspace-source.nix {inherit lib;};
in {
  inherit src;
  cargoDeps = aosWorkspaceVendor;
}
