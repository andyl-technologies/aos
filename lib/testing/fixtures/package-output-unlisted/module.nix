##! Package-output fixture that requests an unlisted dependency.
{
  lib,
  outputs,
  ...
}: {
  options.outputConfinement.hasForbidden = lib.mkOption {type = lib.types.bool;};
  config.outputConfinement.hasForbidden = outputs.dependencies ? forbidden;
}
