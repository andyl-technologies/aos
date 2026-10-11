##! modules/base/kernel.nix — Kernel configuration module
##!
##! Configures kernel tunables, kernel module loading, and optional TCP BBR
##! congestion control through the native kernel providers.
##!
##! These are performance/functionality sysctls — security-focused sysctls
##! belong in modules/security/hardening.nix.
{
  config,
  pkgs,
  lib,
  packageModulesAvailable ? false,
  ...
}: let
  contributedPackages =
    lib.concatLists
    (builtins.attrValues config.aos.kernel.externalPackages);
  kernelPackages = lib.uniqueBy builtins.toString (
    builtins.map
    (package: let
      source =
        if package ? override
        then package
        else pkgs.${package.name}
          or (throw "external kernel package '${package.name}' has no source recipe");
    in
      if builtins.toString source != builtins.toString package
      then throw "external kernel source recipe differs from its retained package artifact"
      else source.override {kernel = config.system.build.kernel;})
    contributedPackages
  );
in {
  imports = lib.optionals (!packageModulesAvailable) [
    ../../pkgs/system/_aos-host-policy/kernel.nix
  ];

  options.aos.kernel = {
    modulePackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      description = ''
        External kernel-module packages built against system.build.kernel.
        Their module trees are merged into the root filesystem and indexed
        together with the in-tree modules. Packages needed before switch-root
        must also be listed in aos.boot.initrd.modulePackages.
      '';
    };

    includeFirmware = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Include selected device firmware in the image and initrd. Set this to
        false for a firmware-free image; firmwarePackages options still record
        the selections to use when inclusion is enabled.
      '';
    };

    firmwarePackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [pkgs.firmware];
      description = ''
        Firmware packages exposed below /usr/lib/firmware in the runtime
        system. Package trees are merged in list order and duplicate paths are
        rejected at image-build time. Early-boot firmware is selected
        separately with aos.boot.initrd.firmwarePackages.
      '';
    };
  };

  config = {
    aos.kernel = {
      modulePackages = kernelPackages;
    };

    aos.boot.recovery.extraPackages = kernelPackages;
    environment.systemPackages = kernelPackages;
  };
}
