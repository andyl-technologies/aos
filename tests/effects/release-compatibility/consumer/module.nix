##! Extends an operation interface from an explicit package dependency.
{lib, ...}: {
  aos.abilities.versioned.operations.echo.result.options.extra = lib.mkOption {
    type = lib.types.bool;
  };
}
