##! Package-import fixture that constructs a lexical sibling escape string.
{
  lib,
  ...
}: {
  imports = ["${builtins.toString ./.}/../package-import-foreign.nix"];
  options.importConfinement.value = lib.mkOption {type = lib.types.str;};
}
