##! Declares a native effect used to exercise OCI graph retention and preflight.
{
  lib,
  package,
  ...
}: {
  aos.abilities.fixture.operations.realize = {
    input.options.message = lib.mkOption {type = lib.types.str;};
    result.options.value = lib.mkOption {type = lib.types.str;};
    handler.program = package;
    effects.sample.input.message = "OCI fixture";
  };
}
