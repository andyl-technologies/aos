##! Roots one explicit immutable Environment instruction and its object bytes.
{
  mkDerivation,
  coreutils,
  lib,
}: {
  generationManifest,
  objects,
}: let
  names = builtins.attrNames objects;
  canonicalNames = builtins.all (name: builtins.match "[0-9a-f]{64}" name != null) names;
  objectCommands = lib.concatMapStringsSep "\n" (name: ''
    source=${lib.escapeShellArg (toString objects.${name})}
    test -f "$source"
    actual="$(${coreutils}/bin/sha256sum "$source")"
    test "''${actual%% *}" = ${lib.escapeShellArg name}
    ${coreutils}/bin/install --mode=0444 "$source" "$out/objects/${name}"
  '') names;
in
  assert canonicalNames;
  assert names != [];
    mkDerivation {
      pname = "aos-environment-provision";
      version = "1";
      src = generationManifest;
      buildDeps = [coreutils];
      runtimeDeps = [];
      propagatedDeps = [];

      phases = [
        {
          name = "install";
          script = ''
            set -eu
            test -f "$src"
            test -s "$src"
            ${coreutils}/bin/mkdir --parents "$out/objects"

            # The existing runtime generation codec validates the complete body.
            # This explicit template header permits only its sandbox rebinding;
            # it is not a signed input, GC receipt or execution authorization.
            printf 'AOSENVT1\000\001\000\000\000\000\000\000' > "$out/instruction-v1"
            ${coreutils}/bin/cat "$src" >> "$out/instruction-v1"
            ${coreutils}/bin/chmod 0444 "$out/instruction-v1"

            ${objectCommands}
          '';
        }
      ];

      meta = {
        description = "Explicit immutable Environment generation template and complete rooted object bytes";
      };
    }
