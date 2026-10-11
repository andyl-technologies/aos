##! Defines device readiness for deferred service sandbox configuration.
{lib, ...}: {
  aos.abilities.device.operations.present = {
    input.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Absolute device path required by the consumer.";
      };
      kind = lib.mkOption {
        type = lib.types.enum ["character" "block"];
        default = "character";
        description = "Required device node type.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Concrete device path verified by the selected handler.";
    };
  };
}
