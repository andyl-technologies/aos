##! Maps authored host session variables into the native PAM domain.
{
  config,
  lib,
  options,
  ...
}: {
  options.aos.login.profile.enable = lib.mkEnableOption "the native system login profile";
  options.environment.sessionVariables = lib.mkOption {
    type = lib.types.attrsOf (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
    default = {};
    extensible = true;
    description = "Variables exported when a PAM session opens.";
  };

  config = lib.mkIf ((config.aos.boot.stage or "host") == "host") (lib.mkMerge [
    (lib.optionalAttrs (options.aos ? pam) {
      aos.pam.sessionVariables = config.environment.sessionVariables;
    })
    (lib.mkIf config.aos.login.profile.enable {
      aos.abilities.configuration.operations.file.effects.host-profile.input = {
        path = "/etc/profile";
        content = import ./profile-text.nix {
          inherit lib;
          path = let
            value = config.environment.sessionVariables.PATH or "/run/wrappers/bin:/var/lib/profiles/system/current/bin:/var/lib/profiles/system/current/sbin";
          in
            if builtins.isList value
            then lib.concatStringsSep ":" value
            else value;
        };
        mode = "0644";
      };
    })
  ]);
}
