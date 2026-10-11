##! Declares locale selection without creating host activation effects.
{
  lib,
  package ? null,
  pkgs ? {},
  ...
}: {
  options.aos.system = {
    ## System locale (LANG environment variable).
    ##
    ## # Examples
    ## ```nix
    ## aos.system.locale = "en_US.UTF-8";
    ## ```
    locale = lib.mkOption {
      type = lib.types.str;
      default = "C.UTF-8";
      description = "System locale (LANG environment variable).";
    };

    localePackages = lib.mkOption {
      extensible = true;
      type = lib.types.listOf lib.types.package;
      default = lib.optional (package != null || pkgs ? glibc-locales) (
        if package != null
        then package
        else pkgs.glibc-locales
      );
      description = "Source-built locale data packages used by the system C library.";
    };
  };
}
