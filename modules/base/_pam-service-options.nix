##! Package-authored PAM service options.
{lib, ...}: let
  types = lib.abilities.types;
  packageOwnedMap = import ../_package-owned-map.nix {inherit lib;};
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
  options.aos.pam.packageServices = lib.mkOption {
    type = packageOwnedMap pamService;
    default = {};
    extensible = true;
    description = "Package-owned PAM service policies consumed by the host authentication module.";
  };
}
