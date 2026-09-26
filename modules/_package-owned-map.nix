##! Shared bounds for package-keyed domain options.
{lib}: value:
lib.abilities.types.map {
  keyMaxLength = 128;
  keySyntax = "local-key-v1";
  maxEntries = 4096;
  inherit value;
}
