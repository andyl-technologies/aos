##! lib/formats.nix — Structured-config format helpers
##!
##! Analog of nixpkgs' `pkgs.formats`. Each factory in this file returns
##! an attrset with:
##!
##!     type      :: lib.types value  — option/submodule type for the format
##!     generate  :: name -> value -> derivation  — serialises a value
##!
##! Unlike nixpkgs, the AOS `lib` is `pkgs`-less at construction time (see
##! `lib/default.nix`), so every factory takes both `lib` and `pkgs` at
##! call time rather than being pre-bound. Call sites write:
##!
##!     fmt = lib.formats.json { inherit lib pkgs; };
##!     fmt.generate "example.json" { foo = 1; }
##!
##! Additional format-specific options live on individual factories
##! (e.g. `lib.formats.ignition { inherit lib pkgs; allowStorageHardware = false; }`).
{
  # No arguments at the file level. Each factory takes its own { lib,
  # pkgs, … } so the file can be imported from `lib/default.nix`
  # without threading lib/pkgs through the library construction
  # fixpoint.
}: {
  ##! # `json`
  ##!
  ##! A general-purpose JSON format. `type` accepts any value that
  ##! `builtins.toJSON` can round-trip (booleans, numbers, strings,
  ##! null, lists, attrsets of the same — recursively). `generate`
  ##! writes a file containing the serialised JSON.
  ##!
  ##! No post-write validation is run; callers that want semantic
  ##! checks (JSON schema, domain validators) should compose a custom
  ##! `generate` around this one or use a format-specific helper like
  ##! `lib.formats.ignition`.
  ##!
  ##! The recursive value type follows nixpkgs'
  ##! `types.serializableValueWith` pattern: the inner `oneOf` refers
  ##! to the outer `jsonValue` via a lazy let-binding, and the outer
  ##! type overrides `name` / `description` so error messages never
  ##! have to force the self-referential `oneOf.name` string.
  json = {
    lib,
    pkgs,
  }: let
    inherit (lib) types;
    baseType = types.oneOf [
      types.bool
      types.int
      types.float
      types.str
      (types.nullOr jsonValue)
      (types.listOf jsonValue)
      (types.attrsOf jsonValue)
    ];
    jsonValue =
      baseType
      // {
        name = "json";
        description = "JSON value";
      };
  in {
    type = jsonValue;
    generate = name: value:
      pkgs.mkDerivation {
        pname = "format-json-${name}";
        version = "0";
        src = null;
        buildDeps = [pkgs.coreutils];
        JSON_CONTENT = builtins.toJSON value;
        phases = [
          {
            name = "emit";
            script = ''
              printf '%s' "$JSON_CONTENT" > $out
            '';
          }
        ];
      };
  };
}
