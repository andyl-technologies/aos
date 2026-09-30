##! Declares an ability whose version is independent of its package release.
{lib, ...}: {
  aos.abilities.versioned = {
    version = "1.4.2";
    operations.echo = {
      input.options.message = lib.mkOption {type = lib.types.str;};
      result.options.message = lib.mkOption {type = lib.types.str;};
    };
  };
}
