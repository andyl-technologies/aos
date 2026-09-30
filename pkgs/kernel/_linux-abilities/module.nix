##! Package-owned Linux boot image and module ABI declarations.
{
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: {
  options.aos.kernel.available = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        package = lib.mkOption {
          type = lib.types.package;
          description = "Immutable kernel package output.";
        };
        bootImage = lib.mkOption {
          type = lib.types.str;
          description = "Bootable image supplied by the kernel package.";
        };
        moduleTree = lib.mkOption {
          type = lib.types.str;
          description = "Loadable modules built against the kernel ABI.";
        };
        release = lib.mkOption {
          type = lib.types.str;
          description = "Kernel ABI release identifier.";
        };
      };
    });
    default = {};
    description = "Kernel artifacts contributed by selected package modules.";
  };

  config.aos.kernel.available.${packageName} = {
    inherit package;
    bootImage = "${package}/boot/vmlinuz-${packageVersion}";
    moduleTree = "${package}/lib/modules/${packageVersion}";
    release = packageVersion;
  };
}
