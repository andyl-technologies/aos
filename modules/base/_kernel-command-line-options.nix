##! Package-authored kernel command-line options.
{lib, ...}: let
  types = lib.abilities.types;
  packageOwnedMap = import ../_package-owned-map.nix {inherit lib;};
  kernelParameter = types.string {
    maxLength = 4096;
    syntax = null;
  };
in {
  options.aos.kernel.commandLineParts = lib.mkOption {
    type = packageOwnedMap (types.list {
      element = kernelParameter;
      maxItems = 256;
      unique = true;
      canonicalOrder = true;
    });
    default = {};
    extensible = true;
    description = "Package-owned kernel command-line fragments consumed by image construction.";
  };
}
