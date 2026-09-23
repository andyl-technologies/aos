##! Evaluates one base module with authenticated native provider packages.
{
  lib,
  pkgs,
}: {
  name,
  module,
  packages,
  extraPackageModules ? [],
  extraModules ? [],
  enableAbilitySelection ? false,
}:
lib.evalModules {
  inherit lib pkgs enableAbilitySelection;
  modules =
    [
      ../../modules/abilities/default.nix
      ../../modules/_package-domain-options.nix
      module
      {
        options = {
          environment.etc = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          environment.systemPackages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
          system.build.kernel = lib.mkOption {
            type = lib.types.package;
            default = pkgs.linux;
          };
          system.checks = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          aos.boot.storage.backend = lib.mkOption {
            type = lib.types.str;
            default = "gpt-partitions";
          };
          aos.boot.kernelParams = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
          };
          aos.boot.recovery.extraPackages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
          aos.kernel.modules = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
          };
          aos.kernel.modulePackages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
          aos.monitoring.hardware.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          aos.zram.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          aos.zram.size = lib.mkOption {
            type = lib.types.str;
            default = "0";
          };
        };
        aos.abilities.environment = {
          authority = "test";
          key = name;
          stage = "host";
        };
      }
      (lib.optionalAttrs (!(builtins.any (package: package.pname == "systemd") packages)) {
        options.systemd.services = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = {};
        };
      })
    ]
    ++ extraModules;
  packageModules =
    builtins.map lib.abilities.authenticatedPackageModuleRecordFor packages
    ++ extraPackageModules;
}
