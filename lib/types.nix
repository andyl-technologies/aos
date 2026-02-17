##! lib/types.nix — Module option type definitions
##!
##! Each type is an attribute set with:
##!
##!     name        :: string         — human-readable type name
##!     description :: string         — longer description for docs
##!     check       :: a -> bool      — predicate testing if a value has this type
##!     merge       :: loc -> [def] -> a  — combine multiple option definitions
##!
##! Where:
##!
##!     loc  = [string]    — option path for error messages (e.g. ["services" "ssh" "port"])
##!     def  = { file :: string; value :: a; }  — a single definition with its source file
##!
##! Parameterized types (listOf, attrsOf, etc.) are functions returning a type.
let
  # Helper: take the last definition's value (last-writer-wins semantics).
  lastValue = _loc: defs: let
    last = builtins.elemAt defs (builtins.length defs - 1);
  in
    last.value;

  # Helper: format an option location for error messages.
  showLoc = loc: builtins.concatStringsSep "." loc;

  # Helper: show the source file and value of a definition.
  showDef = def: "'${builtins.toString def.value}' (defined in ${def.file})";

  # Helper: show all definitions.
  showDefs = defs: builtins.concatStringsSep ", " (builtins.map showDef defs);

  # Helper: check if a value is an order marker
  isOrder = v: builtins.isAttrs v && v ? _type && v._type == "order";

  # Helper: deep merge for submodules
  deepMergeSub = lhs: rhs:
    if builtins.isAttrs lhs && builtins.isAttrs rhs
    then let
      allNames = builtins.attrNames (lhs // rhs);
    in
      builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = let
            lHas = builtins.hasAttr name lhs;
            rHas = builtins.hasAttr name rhs;
          in
            if lHas && rHas
            then deepMergeSub lhs.${name} rhs.${name}
            else if rHas
            then rhs.${name}
            else lhs.${name};
        })
        allNames
      )
    else rhs;
in {
  ## # Primitive types

  bool = {
    name = "bool";
    description = "boolean";
    check = builtins.isBool;
    merge = _loc: defs: let
      val = builtins.elemAt defs (builtins.length defs - 1);
    in
      val.value;
  };

  int = {
    name = "int";
    description = "signed integer";
    check = builtins.isInt;
    merge = lastValue;
  };

  float = {
    name = "float";
    description = "floating point number";
    check = builtins.isFloat;
    merge = lastValue;
  };

  str = {
    name = "str";
    description = "string";
    check = builtins.isString;
    merge = lastValue;
  };

  # lines — concatenates multiple string definitions with newlines
  lines = {
    name = "lines";
    description = "strings concatenated with newlines";
    check = builtins.isString;
    merge = _loc: defs: builtins.concatStringsSep "\n" (builtins.map (d: d.value) defs);
  };

  nonEmptyStr = {
    name = "nonEmptyStr";
    description = "non-empty string";
    check = v: builtins.isString v && builtins.stringLength v > 0;
    merge = loc: defs: let
      val = lastValue loc defs;
    in
      if builtins.stringLength val == 0
      then throw "The option '${showLoc loc}' must be a non-empty string, but is empty."
      else val;
  };

  path = {
    name = "path";
    description = "path";
    check = v: builtins.isPath v || (builtins.isString v && builtins.substring 0 1 v == "/");
    merge = lastValue;
  };

  package = {
    name = "package";
    description = "package (derivation)";
    check = v: builtins.isAttrs v && (v ? outPath || v ? drvPath || v ? type && v.type == "derivation");
    merge = lastValue;
  };

  attrs = {
    name = "attrs";
    description = "attribute set";
    check = builtins.isAttrs;
    merge = _loc: defs: builtins.foldl' (acc: def: acc // def.value) {} defs;
  };

  anything = {
    name = "anything";
    description = "any value";
    check = _: true;
    merge = _loc: defs: let
      last = builtins.elemAt defs (builtins.length defs - 1);
    in
      # If all defs are attrsets, merge them; otherwise last wins.
      if builtins.all (d: builtins.isAttrs d.value) defs
      then builtins.foldl' (acc: def: acc // def.value) {} defs
      else if builtins.all (d: builtins.isList d.value) defs
      then builtins.concatLists (builtins.map (d: d.value) defs)
      else last.value;
  };

  ## # Network types

  port = {
    name = "port";
    description = "TCP/UDP port number (1-65535)";
    check = v: builtins.isInt v && v >= 1 && v <= 65535;
    merge = loc: defs: let
      val = lastValue loc defs;
    in
      if val < 1 || val > 65535
      then throw "The option '${showLoc loc}' must be a port (1-65535), but is ${builtins.toString val}."
      else val;
  };

  ## # Parameterized types

  ## # Type
  ## `[a] -> type`
  enum = allowedValues: {
    name = "enum";
    description = "one of ${builtins.toJSON allowedValues}";
    check = v: builtins.any (a: a == v) allowedValues;
    merge = loc: defs: let
      val = lastValue loc defs;
    in
      if builtins.any (a: a == val) allowedValues
      then val
      else throw "The option '${showLoc loc}' must be one of ${builtins.toJSON allowedValues}, but is '${builtins.toJSON val}'.";
  };

  ## Supports mkBefore/mkAfter ordering markers on individual list elements.
  ## # Type
  ## `type -> type`
  listOf = elemType: {
    name = "listOf(${elemType.name})";
    description = "list of ${elemType.description}";
    check = v: builtins.isList v;
    merge = _loc: defs: let
      # Collect all elements from all definitions, unwrapping order markers
      processElem = elem:
        if isOrder elem
        then {
          value = elem._value;
          priority = elem._priority;
        }
        else {
          value = elem;
          priority = 1000;
        };
      allElems = builtins.concatLists (builtins.map (d: builtins.map processElem d.value) defs);
      # Sort by priority (lower = earlier in list)
      sorted = builtins.sort (a: b: a.priority < b.priority) allElems;
    in
      builtins.map (e: e.value) sorted;
  };

  ## # Type
  ## `type -> type`
  attrsOf = elemType: {
    name = "attrsOf(${elemType.name})";
    description = "attribute set of ${elemType.description}";
    check = v: builtins.isAttrs v && builtins.all elemType.check (builtins.attrValues v);
    merge = loc: defs: let
      allKeys = builtins.concatLists (builtins.map (d: builtins.attrNames d.value) defs);
      uniqueKeys = let
        go = acc: remaining:
          if remaining == []
          then acc
          else let
            h = builtins.elemAt remaining 0;
            t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
          in
            if builtins.any (x: x == h) acc
            then go acc t
            else go (acc ++ [h]) t;
      in
        go [] allKeys;
    in
      builtins.listToAttrs (
        builtins.map (
          key: let
            keyDefs = builtins.filter (d: builtins.hasAttr key d.value) (
              builtins.map (d: {
                file = d.file;
                value = d.value;
              })
              defs
            );
            valueDefs =
              builtins.map (d: {
                file = d.file;
                value = d.value.${key};
              })
              keyDefs;
          in {
            name = key;
            value = elemType.merge (loc ++ [key]) valueDefs;
          }
        )
        uniqueKeys
      );
  };

  ## # Type
  ## `type -> type`
  nullOr = elemType: {
    name = "nullOr(${elemType.name})";
    description = "${elemType.description} or null";
    check = v: v == null || elemType.check v;
    merge = loc: defs: let
      val = lastValue loc defs;
    in
      if val == null
      then null
      else
        elemType.merge loc [
          {
            file = (builtins.elemAt defs (builtins.length defs - 1)).file;
            value = val;
          }
        ];
  };

  ## # Type
  ## `type -> type -> type`
  either = type1: type2: {
    name = "either(${type1.name},${type2.name})";
    description = "${type1.description} or ${type2.description}";
    check = v: type1.check v || type2.check v;
    merge = loc: defs: let
      val = lastValue loc defs;
      lastDef = builtins.elemAt defs (builtins.length defs - 1);
    in
      if type1.check val
      then type1.merge loc [lastDef]
      else if type2.check val
      then type2.merge loc [lastDef]
      else throw "The option '${showLoc loc}' does not match either ${type1.name} or ${type2.name}.";
  };

  ## # Type
  ## `[type] -> type`
  oneOf = types: {
    name = "oneOf(${builtins.concatStringsSep "," (builtins.map (t: t.name) types)})";
    description = "one of ${builtins.concatStringsSep ", " (builtins.map (t: t.description) types)}";
    check = v: builtins.any (t: t.check v) types;
    merge = loc: defs: let
      val = lastValue loc defs;
      lastDef = builtins.elemAt defs (builtins.length defs - 1);
      matchingType =
        builtins.foldl' (
          acc: t:
            if acc != null
            then acc
            else if t.check val
            then t
            else null
        )
        null
        types;
    in
      if matchingType != null
      then matchingType.merge loc [lastDef]
      else throw "The option '${showLoc loc}' does not match any of the expected types.";
  };

  ## Uses recursive deep merge instead of shallow (//) merge.
  ## # Type
  ## `(attrset | function) -> type`
  submodule = moduleOrFn: {
    name = "submodule";
    description = "submodule";
    check = builtins.isAttrs;
    merge = loc: defs: builtins.foldl' (acc: def: deepMergeSub acc def.value) {} defs;
    _submodule = moduleOrFn;
  };

  ## # Type combinators

  ## # Type
  ## `type -> (a -> b) -> type -> type`
  coercedTo = fromType: coercion: toType: {
    name = "coercedTo(${fromType.name},${toType.name})";
    description = "${fromType.description} convertible to ${toType.description}";
    check = v: fromType.check v || toType.check v;
    merge = loc: defs: let
      coerced =
        builtins.map (
          d:
            if fromType.check d.value
            then d // {value = coercion d.value;}
            else d
        )
        defs;
    in
      toType.merge loc coerced;
  };

  ## # Type
  ## `type -> type`
  uniq = elemType: {
    name = "uniq(${elemType.name})";
    description = "unique ${elemType.description}";
    check = elemType.check;
    merge = loc: defs:
      if builtins.length defs == 1
      then (builtins.elemAt defs 0).value
      else let
        val = (builtins.elemAt defs 0).value;
        allSame = builtins.all (d: d.value == val) defs;
      in
        if allSame
        then val
        else throw "The option '${showLoc loc}' has conflicting definitions. It must have a unique value.";
  };
}
