##! lib/formats/toml.nix — General-purpose TOML format factory
##!
##! Unlike JSON and YAML 1.2, TOML is not a superset of JSON, so the
##! output cannot be produced by `builtins.toJSON`. This factory
##! carries a small pure-Nix TOML emitter; no external converter is
##! needed, which keeps the factory hermetic.
##!
##! Supported value types:
##!
##!   bool, int, float, string   → TOML scalars
##!   list                       → inline arrays (`[1, 2, 3]`)
##!   attrset                    → tables; at the top of a table
##!                                scalar/inline-array keys come first,
##!                                then `[[aot]]` entries, then nested
##!                                `[sub.table]` sections
##!   null                       → pruned (TOML has no null)
##!
##! A list of attrsets at a non-root position becomes an array of
##! tables (`[[parent.name]]`). A list with any non-attrset entry, or
##! a mixed list, stays inline.
##!
##! Keys that match `[A-Za-z0-9_-]+` are emitted bare; everything
##! else (dots, spaces, unicode) is double-quoted.
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
    (types.nullOr tomlValue)
    (types.listOf tomlValue)
    (types.attrsOf tomlValue)
  ];
  tomlValue =
    baseType
    // {
      name = "toml";
      description = "TOML value";
      # TOML values are recursively nested.  Publishing the recursively
      # expanded `oneOf` would never reach a finite documentation object, so
      # expose the stable format contract at this boundary instead.
      _aosDocType = {
        kind = "opaque";
        signature = "TOML value";
      };
    };

  inherit (builtins) isAttrs isBool isFloat isInt isList isString;

  # A bare key is a non-empty string of [A-Za-z0-9_-]. Anything else
  # is emitted as a quoted key.
  isBareKey = s: s != "" && builtins.match "[A-Za-z0-9_-]+" s != null;

  # Nix string literals have no backspace (0x08) or formfeed (0x0C)
  # escapes — `\b` / `\f` are literal `b` / `f` — so we can't round-
  # trip those control characters through a Nix-side escape table.
  # Escaping the five that Nix does expose covers every string that
  # made it in through a Nix literal.
  escapeString = s:
    "\""
    + builtins.replaceStrings
    ["\\" "\"" "\n" "\t" "\r"]
    ["\\\\" "\\\"" "\\n" "\\t" "\\r"]
    s
    + "\"";

  encodeKey = k:
    if isBareKey k
    then k
    else escapeString k;

  joinKeys = ks: builtins.concatStringsSep "." (builtins.map encodeKey ks);

  # Remove null-valued keys from an attrset (recursively via pruneValue).
  pruneAttrs = set: let
    pairs = builtins.concatMap (
      n: let
        pv = pruneValue set.${n};
      in
        if pv == null
        then []
        else [
          {
            name = n;
            value = pv;
          }
        ]
    ) (builtins.attrNames set);
  in
    builtins.listToAttrs pairs;

  pruneValue = v:
    if v == null
    then null
    else if isAttrs v
    then pruneAttrs v
    else if isList v
    then builtins.filter (x: x != null) (builtins.map pruneValue v)
    else v;

  # Array of tables: a non-empty list in which every element is an
  # attrset. Inline arrays of scalars / mixed arrays are not AOTs.
  isArrayOfTables = v:
    isList v && v != [] && builtins.all isAttrs v;

  # Inline form: scalars, inline tables, and inline arrays.
  encodeInline = v:
    if isBool v
    then
      if v
      then "true"
      else "false"
    else if isInt v
    then toString v
    else if isFloat v
    then toString v
    else if isString v
    then escapeString v
    else if isList v
    then "[" + builtins.concatStringsSep ", " (builtins.map encodeInline v) + "]"
    else if isAttrs v
    then let
      names = builtins.attrNames v;
    in
      if names == []
      then "{}"
      else
        "{ "
        + builtins.concatStringsSep ", " (
          builtins.map (n: "${encodeKey n} = ${encodeInline v.${n}}") names
        )
        + " }"
    else throw "lib.formats.toml: cannot encode value of type ${builtins.typeOf v}";

  # Triage the keys of a table into:
  #   kv     — scalars, inline arrays, or inline tables (emitted
  #            directly under the current header).
  #   aot    — lists of attrsets (emitted as `[[prefix.name]]` blocks).
  #   table  — attrsets (emitted as `[prefix.name]` sections).
  #
  # An empty attrset is treated as `kv` so it serialises to `name = {}`
  # rather than an empty `[name]` header (TOML allows empty tables but
  # the inline form is unambiguous).
  triage = set: let
    names = builtins.attrNames set;
  in
    builtins.map (n: let
      v = set.${n};
    in
      if isAttrs v && v != {}
      then {
        kind = "table";
        inherit n v;
      }
      else if isArrayOfTables v
      then {
        kind = "aot";
        inherit n v;
      }
      else {
        kind = "kv";
        inherit n v;
      })
    names;

  # Render the body of a table (the KV lines plus any nested sections
  # introduced by sub-tables and arrays of tables) at `prefix`.
  renderBody = prefix: set: let
    parts = triage set;
    kvs = builtins.filter (p: p.kind == "kv") parts;
    aots = builtins.filter (p: p.kind == "aot") parts;
    tables = builtins.filter (p: p.kind == "table") parts;

    kvLines = builtins.concatStringsSep "" (
      builtins.map ({
        n,
        v,
        ...
      }: "${encodeKey n} = ${encodeInline v}\n")
      kvs
    );

    aotBlocks = builtins.concatStringsSep "" (
      builtins.map ({
        n,
        v,
        ...
      }: let
        p = prefix ++ [n];
        header = "[[" + joinKeys p + "]]\n";
      in
        builtins.concatStringsSep "" (
          builtins.map (item: "\n" + header + renderBody p item) v
        ))
      aots
    );

    # Emit a `[section]` header only if the sub-table has direct
    # scalar/aot content. A table whose only entries are further
    # sub-tables is implicit under TOML's dotted-key rules, so the
    # redundant parent header (`[nested]` preceding `[nested.deep]`)
    # just clutters the output.
    tableBlocks = builtins.concatStringsSep "" (
      builtins.map ({
        n,
        v,
        ...
      }: let
        p = prefix ++ [n];
        subParts = triage v;
        subHasOwn =
          builtins.any (sp: sp.kind == "kv" || sp.kind == "aot")
          subParts;
        header =
          if subHasOwn
          then "\n[" + joinKeys p + "]\n"
          else "";
      in
        header + renderBody p v)
      tables
    );
  in
    kvLines + aotBlocks + tableBlocks;

  toTOML = value: let
    pruned = pruneValue value;
    root =
      if pruned == null
      then {}
      else pruned;
  in
    if !isAttrs root
    then throw "lib.formats.toml: top-level value must be an attrset, got ${builtins.typeOf root}"
    else renderBody [] root;
in {
  inherit toTOML;

  type = tomlValue;
  generate = name: value:
    pkgs.mkDerivation {
      pname = "format-toml-${name}";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils];
      content = toTOML value;
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
