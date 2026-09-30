##! modules/packages.nix - Image-baked package selection.
##!
##! Selects package payloads whose authenticated native modules and release
##! artifacts participate in the host fixed point. Package deployment envelopes remain
##! the single source for module, operation, handler, and artifact
##! metadata; this module does not reconstruct a parallel package catalog.
{
  config,
  lib,
  ...
}: let
  packageNamePattern = "[A-Za-z0-9][A-Za-z0-9+._=-]*";

  packageType = lib.types.submodule ({name, ...}: {
    options = {
      package = lib.mkOption {
        type = lib.types.package;
        description = ''
          Package derivation admitted as `aos.packages.${name}`. Its
          authenticated native module participates in the target fixed point
          whether or not the payload is bundled.
        '';
      };

      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether this package's authenticated native module participates in
          the target fixed point. Bundling the payload also admits the module.
        '';
      };

      bundle = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether this package's payload is retained in the image. The native
          module is admitted by the package declaration itself, so
          package-owned options remain available without bundling executables.
        '';
      };
    };
  });

  bundledPackages =
    lib.filterAttrs (_: package: package.bundle) config.aos.packages;
in {
  options.aos.packages = lib.mkOption {
    type = lib.types.attrsOf packageType;
    default = {};
    description = ''
      Packages available to the target. `enable` admits a native module without
      retaining its payload, while `bundle` admits the module and retains the
      payload in the image.
    '';
  };

  config = {
    assertions = lib.concatLists (lib.mapAttrsToList (
        name: package: [
          {
            assertion = builtins.match packageNamePattern name != null;
            message = ''
              aos.packages."${name}": package names must match
              ${packageNamePattern}.
            '';
          }
          {
            assertion = !package.enable || package.package ? module;
            message = ''
              aos.packages."${name}" must select a package with one native
              module source when its configuration is enabled.
            '';
          }
          {
            assertion = (package.package.catalogName or package.package.pname or package.package.name) == name;
            message = ''
              aos.packages."${name}" selects a package whose native identity
              does not match the selection key and payload.
            '';
          }
        ]
      )
      config.aos.packages);

    environment.systemPackages =
      lib.mapAttrsToList (_: package: package.package) bundledPackages;
  };
}
