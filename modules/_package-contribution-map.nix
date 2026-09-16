##! Shared bounds for package-keyed feature contributions.
{lib}: value:
lib.abilities.types.map {
  keyMaxLength = 128;
  keySyntax = "local-key-v1";
  maxEntries = 4096;
  inherit value;
}
