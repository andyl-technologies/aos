##! Package-authored PAM service contributions.
{lib, ...}: let
  types = lib.abilities.types;
  contributionMap = import ../_package-contribution-map.nix {inherit lib;};
  pamService = types.record {
    fields = {
      unixAuth = types.boolean;
      startSession = types.boolean;
      setLoginUid = types.boolean;
    };
  };
in {
  options.aos.contributions.pamServices = lib.mkOption {
    type = contributionMap pamService;
    default = {};
    contributable = true;
    description = "Package-owned PAM service policies consumed by the host authentication module.";
  };
}
