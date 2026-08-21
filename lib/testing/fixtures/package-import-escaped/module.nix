##! Package-import confinement fixture that attempts a sibling escape.
{lib, ...}: {
  imports = [../package-import-foreign.nix];
  options.importConfinement.value = lib.mkOption {type = lib.types.str;};
}
