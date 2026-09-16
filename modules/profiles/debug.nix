##! Debug tools profile.
##!
##! Adds diagnostic tools and selects the package-owned util-linux console
##! services for local VM access. The host and initrd fixed points evaluate the
##! same getty module under their own stage identities.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.profiles.debug;
in {
  options.aos.profiles.debug = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = ''
        Enable the debug profile. Adds diagnostic tools and sets the system
        security policy to the debug level.
      '';
    };

    autologin = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = ''
        Unlock root and run package-owned autologin gettys on the primary
        virtual and serial consoles for local VM testing.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      aos.security.level = lib.mkDefault "debug";
    }

    (lib.mkIf cfg.autologin {
      # Selecting util-linux admits its native getty module to the host fixed
      # point. The typed package option enables its host service requests.
      environment.systemPackages = [pkgs.util-linux];
      aos.services.getty.autologin.enable = true;

      # Stage 1 evaluates the same authenticated package module with an explicit
      # initrd identity and ordinary stage-local configuration.
      aos.boot.initrd.packageRoots = [pkgs.util-linux];
      aos.abilities.stages.initrd = {
        modules = [
          {
            aos.services.getty.autologin = {
              enable = true;
              stage = "initrd";
            };
          }
        ];
      };

      # The gettys bypass login(1), so preserve the development image's empty
      # root password for other local console tools that inspect shadow(5).
      environment.etc."shadow" = lib.mkForce {
        text = ''
          root:::0:99999:7:::
          nobody:!*::0:99999:7:::
        '';
        mode = "0000";
      };
    })
  ]);
}
