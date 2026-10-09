##! Shared operation contract imported as a package module dependency.
{lib, ...}: {
  aos.abilities.echo.operations.run = {
    input.options.message = lib.mkOption {
      type = lib.types.str;
      description = "Message returned by the echo operation.";
    };
    result.options.message = lib.mkOption {
      type = lib.types.str;
      description = "Message returned by the selected handler.";
    };
  };
}
