##! Kernel-module operations supplied by the kmod package.
{
  lib,
  package,
  ...
}: {
  aos.abilities.kernelModules.operations.ensure = {
    input.options = {
      modules = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Distinct kernel module names to load.";
      };
      required = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Fail activation when a requested module cannot be loaded.";
      };
    };

    result.options = {
      loaded = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Requested modules observed in the running kernel.";
      };
      unavailable = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Optional requested modules that could not be loaded.";
      };
    };

    handler.program = package;
  };
}
