##! Package-authored PAM service contributions.
{lib, ...}: let
  types = lib.abilities.types;
  contributionMap = import ../_package-contribution-map.nix {inherit lib;};
  pamService = types.record {
    fields = {
      unixAuth = types.boolean;
      startSession = types.boolean;
      setLoginUid = types.boolean;
      useDefaultRules = {
        type = types.optional types.boolean;
        optional = true;
      };
      text = {
        type = types.optional (types.string {
          maxLength = 65536;
          syntax = null;
        });
        optional = true;
      };
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
