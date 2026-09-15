##! Evaluates one base module with authenticated native provider packages.
{
  lib,
  pkgs,
}: {
  name,
  module,
  packages,
}: let
  packageModule = package: {
    inherit (package) version;
    name = package.pname;
    module = package.abilities._module;
    outputs = {
      self = builtins.toString package;
      dependencies = {};
    };
  };
in
  lib.evalModules {
    inherit lib pkgs;
    modules = [
      lib.abilities.module
      module
      {
        options = {
          environment.etc = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          system.checks = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          systemd.services = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
        };
        aos.abilities.environment = {
          authority = "test";
          key = name;
          stage = "host";
        };
      }
    ];
    packageModules = builtins.map packageModule packages;
  }
