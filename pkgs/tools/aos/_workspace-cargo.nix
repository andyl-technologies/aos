##! Shared source and patched registry vendor for independent sandbox roles.
##!
##! The supplied package-set fetcher enforces the canonical source patch recipe.
##! Only source inputs are shared; role compiler artifacts stay independent.
{
  lib,
  fetchCargoVendor,
}: let
  src = import ./_workspace-source.nix {inherit lib;};
in {
  inherit src;
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-vendor-0.1.0";
    sourceRoot = "source/crates";
    hash = import ../crucible/_cargo-deps-hash.nix;
  };
}
