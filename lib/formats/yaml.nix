##! lib/formats/yaml.nix — General-purpose YAML format factory
##!
##! Accepts any value that `builtins.toJSON` can round-trip. The
##! output is written as JSON, which is a strict subset of YAML 1.2
##! (and — because JSON requires every string to be double-quoted —
##! also avoids the YAML 1.1 scalar-ambiguity pitfalls where bare
##! `yes`/`no`/`on`/`off` or numeric-looking strings would otherwise
##! be reinterpreted). Every mainstream YAML parser accepts JSON
##! verbatim, so the result round-trips as YAML wherever it is
##! consumed.
##!
##! This keeps the factory fully hermetic: no Python, no remarshal,
##! no external YAML emitter — just `builtins.toJSON`. If a caller
##! one day needs a pretty-printed block-style rendering (for human
##! review rather than machine consumption), they should compose a
##! dedicated generator on top of this type; the `type` field alone
##! is reusable independently of `generate`.
##!
##! The value type mirrors `lib.formats.json` — a self-referential
##! `oneOf` wrapped in a let-binding so error messages never force
##! the recursive name string.
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
    (types.nullOr yamlValue)
    (types.listOf yamlValue)
    (types.attrsOf yamlValue)
  ];
  yamlValue =
    baseType
    // {
      name = "yaml";
      description = "YAML value";
      # YAML values are recursive; a finite opaque format node is the
      # canonical structured-documentation representation.
      _aosDocType = {
        kind = "opaque";
        signature = "YAML value";
      };
    };
in {
  type = yamlValue;
  generate = name: value:
    pkgs.mkDerivation {
      pname = "format-yaml-${name}";
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
