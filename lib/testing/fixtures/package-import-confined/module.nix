##! Package-import confinement fixture with an in-root child.
{
  lib,
  ...
}: {
  imports = [./inside.nix];
  options.importConfinement.value = lib.mkOption {type = lib.types.str;};
}
