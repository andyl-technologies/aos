##! modules/packages.nix - Image-baked package selection.
##!
##! Selects package payloads whose authenticated native modules and release
##! artifacts participate in the host fixed point. Package contracts remain
##! the single source for module, interface, implementation, and artifact
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
          Package derivation selected as `aos.packages.${name}`. The package
          must carry its authenticated contract and native module outputs.
        '';
      };

      bundle = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether this package participates in the image's checked package and
          ability selection. Package-owned options determine runtime behavior.
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
      Packages selected into the image's authenticated package-module fixed
      point. Each selected package is retained through its native contract.
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
            assertion = package.package ? contract && package.package ? module;
            message = ''
              aos.packages."${name}" must select a package with one native
              contract and package-module output.
            '';
          }
          {
            assertion =
              !(package.package ? contract)
              || (
                package.package.contract.value.package.name == package.package.pname
                && package.package.contract.value.package.name == name
              );
            message = ''
              aos.packages."${name}" selects a contract whose package identity
              does not match the selection key and payload.
            '';
          }
        ])
      config.aos.packages);

    environment.systemPackages =
      lib.mapAttrsToList (_: package: package.package) bundledPackages;
  };
}
