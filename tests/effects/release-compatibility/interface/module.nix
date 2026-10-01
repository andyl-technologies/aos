##! Declares an operation interface governed by its owning package release.
{lib, ...}: {
  aos.abilities.versioned.operations.echo = {
    input.options.message = lib.mkOption {type = lib.types.str;};
    result.options.message = lib.mkOption {type = lib.types.str;};
  };
}
