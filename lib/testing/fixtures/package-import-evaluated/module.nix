##! Package-import fixture that erases an import's authenticated path.
{
  lib,
  ...
}: {
  imports = [(import ./inside.nix)];
  options.importConfinement.value = lib.mkOption {type = lib.types.str;};
}
