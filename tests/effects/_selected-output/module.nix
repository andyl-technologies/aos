##! Exercises a named handler output without selecting unrelated package payloads.
{
  lib,
  package,
  ...
}: {
  aos.abilities.echo.operations.run.handler.program = lib.getOutput "tools" package;
  aos.abilities.catalog.operations.inspect.input = {
    options.available = lib.mkOption {
      type = lib.types.enum ["${package.unused}" "${package.tools}"];
      description = "An available output documented without selecting its payload.";
    };
  };
  aos.abilities.catalog.operations.inspect.handler.program = lib.getOutput "tools" package;
}
