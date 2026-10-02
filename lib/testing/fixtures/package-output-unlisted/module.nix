##! Package-output fixture that requests an unlisted dependency.
{
  lib,
  dependencies,
  ...
}: {
  options.outputConfinement.hasForbidden = lib.mkOption {type = lib.types.bool;};
  config.outputConfinement.hasForbidden = dependencies ? forbidden;
}
