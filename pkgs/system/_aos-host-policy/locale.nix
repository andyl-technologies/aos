##! Retains locale selection, session variables, and login files for host replay.
{
  config,
  lib,
  ...
}: let
  session = config.environment.sessionVariables;
  sessionValue = name: let
    value = session.${name};
  in
    if builtins.isList value
    then lib.concatStringsSep ":" value
    else value;
in {
  config = lib.mkIf ((config.aos.boot.stage or "host") == "host") {
    environment.sessionVariables = {
      LANG = lib.mkDefault config.aos.system.locale;
      LOCPATH = lib.mkDefault (lib.concatStringsSep ":" (map (package: "${package}/lib/locale") config.aos.system.localePackages));
    };

    # Login fragments run after PAM; derive them from the same final variables
    # so an image default cannot undo retained operator session configuration.
    aos.abilities.configuration.operations.file.effects = {
      host-locale-profile.input = {
        path = "/etc/profile.d/20-locale.sh";
        mode = "0444";
        content = ''
          export LANG=${lib.escapeShellArg (sessionValue "LANG")}
          export LOCPATH=${lib.escapeShellArg (sessionValue "LOCPATH")}
        '';
      };
      host-locale-conf.input = {
        path = "/etc/locale.conf";
        mode = "0444";
        content = ''
          LANG=${lib.escapeShellArg (sessionValue "LANG")}
        '';
      };
    };
  };
}
