##! Package-authored kernel command-line contributions.
{lib, ...}: let
  types = lib.abilities.types;
  contributionMap = import ../_package-contribution-map.nix {inherit lib;};
  kernelParameter = types.string {
    maxLength = 4096;
    syntax = null;
  };
in {
  options.aos.contributions.kernelParameters = lib.mkOption {
    type = contributionMap (types.list {
      element = kernelParameter;
      maxItems = 256;
      unique = true;
      canonicalOrder = true;
    });
    default = {};
    contributable = true;
    description = "Package-owned kernel command-line fragments consumed by image construction.";
  };
}
