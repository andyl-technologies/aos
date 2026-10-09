##! Native transaction boot preparation interface and implementation.
{
  lib,
  package,
  ...
}: {
  aos.abilities.bootPreparation.operations.prepare = {
    input.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Immutable store executable that performs this boot preparation.";
      };
      arguments = lib.mkOption {
        type = lib.types.listOf (lib.types.deferred lib.types.str);
        default = [];
        description = "Checked command arguments, including resolved effect outputs.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Logical identity whose preparation completed.";
    };
    handler.program = package;
  };
}
