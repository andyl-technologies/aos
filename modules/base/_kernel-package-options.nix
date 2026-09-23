##! Package-authored external kernel package requirements.
{lib, ...}: let
  types = lib.abilities.types;
  packageOwnedMap = import ../_package-owned-map.nix {inherit lib;};
in {
  options.aos.kernel.externalPackages = lib.mkOption {
    type = packageOwnedMap (types.list {
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
