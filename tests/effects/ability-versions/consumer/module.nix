##! Adds operation declarations without claiming the dependency's version.
{lib, ...}: {
  aos.abilities.versioned.operations.echo.result.options.extra = lib.mkOption {
    type = lib.types.bool;
  };
}
