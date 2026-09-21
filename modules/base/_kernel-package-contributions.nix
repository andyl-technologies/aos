##! Package-authored external kernel package requirements.
{lib, ...}: let
  types = lib.abilities.types;
  contributionMap = import ../_package-contribution-map.nix {inherit lib;};
in {
  options.aos.contributions.kernelPackages = lib.mkOption {
    type = contributionMap (types.list {
      element = types.packageOutputSelector;
      maxItems = 64;
      unique = true;
      canonicalOrder = true;
    });
    default = {};
    contributable = true;
    description = ''
      Package-owned source packages rebuilt against the selected kernel and
      retained in the running and recovery environments.
    '';
  };
}
