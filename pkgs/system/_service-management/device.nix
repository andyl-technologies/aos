##! Defines device readiness for deferred service sandbox configuration.
{lib, ...}: {
  aos.abilities.device.operations.present = {
    input.options.path = lib.mkOption {
      type = lib.types.str;
      description = "Absolute device path required by the consumer.";
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Concrete device path verified by the selected handler.";
    };
  };
}
