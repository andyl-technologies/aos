##! lib/formats/json.nix — General-purpose JSON format factory
##!
##! A general-purpose JSON format. `type` accepts any value that
##! `builtins.toJSON` can round-trip (booleans, numbers, strings,
##! null, lists, attrsets of the same — recursively). `generate`
##! writes a file containing the serialised JSON.
##!
##! No post-write validation is run; callers that want semantic
##! checks (JSON schema, domain validators) should compose a custom
##! `generate` around this one or use a format-specific helper.
##!
##! The recursive value type follows nixpkgs'
##! `types.serializableValueWith` pattern: the inner `oneOf` refers
##! to the outer `jsonValue` via a lazy let-binding, and the outer
##! type overrides `name` / `description` so error messages never
##! have to force the self-referential `oneOf.name` string.
{
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
      # JSON values are recursive; keep their published type finite while
      # retaining the precise validation contract in `baseType`.
      _aosDocType = {
        kind = "opaque";
        signature = "JSON value";
      };
    };
in {
  type = jsonValue;
  generate = name: value:
    pkgs.mkDerivation {
      pname = "format-json-${name}";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils];
      content = builtins.toJSON value;
      passAsFile = ["content"];
      OUTPUT_NAME = name;
      phases = [
        {
          name = "emit";
          script = ''
            cp "$contentPath" "$out/$OUTPUT_NAME"
          '';
        }
      ];
    };
}
