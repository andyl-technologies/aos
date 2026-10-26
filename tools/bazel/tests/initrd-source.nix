##! Exercises standalone initrd compilation independently of package installation.
{
  system ? builtins.currentSystem,
  sourceInventory ? ../metadata/initrd-preparation-inventory.json,
  bootTools ? null,
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  pkgs.callPackage ../../../pkgs/boot/_aos-boot-preparations-bazel-build.nix (
    {inherit sourceInventory;}
    // pkgs.lib.optionalAttrs (bootTools != null) {aosBazelBootTools = bootTools;}
  )
