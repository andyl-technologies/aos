##! Linux kernel-tunable operations supplied by the procfs package.
{
  config,
  lib,
  package,
  ...
}: {
  options.aos.kernel = {
    sysctl = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      extensible = true;
      description = "Merged kernel tunables converged by one owning effect.";
    };
    tunablePrerequisites = lib.mkOption {
      type = lib.types.listOf lib.types.effectOutput;
      default = [];
      extensible = true;
      description = "Native resources established before the shared kernel-tunable effect.";
    };
  };

  aos.abilities.kernelTunables.operations.ensure = {
    input.options.values = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      description = "Kernel tunable keys and their desired values.";
    };

    result.options.values = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      description = "Values observed in procfs after convergence.";
    };

    handler.program = package;
    effects.settings = lib.mkIf (config.aos.kernel.sysctl != {}) {
      input.values = config.aos.kernel.sysctl;
      after = config.aos.kernel.tunablePrerequisites;
    };
  };
}
