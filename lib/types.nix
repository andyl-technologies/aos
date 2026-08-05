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
##!
##! `evalSubmodule` is an optional callback supplied by `lib/default.nix`. When
##! present, `submodule`'s merge function delegates to it so that nested
##! modules are evaluated with full nixpkgs semantics (defaults fire,
##! `mkIf`/`mkMerge`/`mkDefault` inside submodules take effect, per-option
##! type checking runs). When `null` (only during bootstrap, before the
##! modules engine is available), submodules fall back to a permissive deep
##! merge that preserves the definitions but skips option processing.
{evalSubmodule ? null}: let
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

  # Helper: check if a value is an override (mkDefault / mkForce / mkOverride)
  # marker, matching the convention used by lib/modules.nix.
  isOverride = v: builtins.isAttrs v && v ? _type && v._type == "override";

  # Helper: check if a value is an `mkIf` conditional marker.
  isMkIf = v: builtins.isAttrs v && v ? _type && v._type == "if";

  # Helper: check if a value is an `mkMerge` marker.
  isMkMerge = v: builtins.isAttrs v && v ? _type && v._type == "merge";

  # Recursively peel mkIf / mkMerge / override markers off a single def
  # value, accumulating priority and conditions as we go. Returns a list
  # of sub-defs (one mkMerge can produce multiple). Each sub-def has the
  # shape `{ file; value; _priority; _condition; }` where `_condition`
  # is the logical AND of every mkIf condition seen along the way, and
  # `_priority` is the innermost override priority (default 100).
  #
  # This is the sub-attribute equivalent of what `lib/modules.nix`'s
  # `collectDefsAtPath` + `activeDefs` + `unwrappedDefs` pipeline does at
  # the option level. Without it, nested patterns like
  #     `serviceConfig.ExecStart = lib.mkDefault "…";`
  # or
  #     `environment.PATH = lib.mkIf (path != []) "…";`
  # inside a submodule's `config` block would leak the raw marker into
  # the final value and crash the type's merge function.
  peelDef = def: condition: priority: value:
    if isOverride value
    then peelDef def condition value._priority value._value
    else if isMkIf value
    then peelDef def (condition && value._condition) priority value._value
    else if isMkMerge value
    then builtins.concatLists (builtins.map (v: peelDef def condition priority v) value._values)
    else [
      (def
        // {
        inherit value;
        _priority = priority;
        _condition = condition;
      })
    ];

  # Given a list of defs whose values may be wrapped in any combination
  # of `mkIf` / `mkMerge` / `mkDefault` / `mkForce` / `mkOverride`, peel
  # all markers off, drop defs whose mkIf conditions are false, and keep
  # only the defs at the winning (lowest) override priority.
  peelProperties = defs: let
    peeled = builtins.concatLists (
      builtins.map (d: peelDef d true (d._priority or 100) d.value) defs
    );
  in
    builtins.filter (d: d._condition) peeled;

  dischargeProperties = defs: let
    active = peelProperties defs;
    minPriority =
      builtins.foldl' (
        acc: d:
          if d._priority < acc
          then d._priority
          else acc
      )
      9999
      active;
  in
    builtins.filter (d: d._priority == minPriority) active;

  # Helper: deep merge two attrsets (used as the submodule bootstrap fallback
  # and as the final deep-merge step for submodule definitions).
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
in rec {
  ## # Type construction helpers
  ##
  ## These are not types themselves; they help build custom types that
  ## plug into the merge pipeline. Exposed so ported nixpkgs code that
  ## uses `lib.mkOptionType` / `lib.mergeEqualOption` keeps working.

  ## Build a type from its fields. Missing fields get sensible defaults:
  ##   description defaults to `name`
  ##   check defaults to `_: true` (accepts anything)
  ##   merge defaults to `lastValue`
  ## # Type
  ## `{ name, description?, check?, merge?, ... } -> type`
  mkOptionType = {
    name,
    description ? name,
    check ? (_: true),
    merge ? lastValue,
    ...
  }: {
    inherit name description check merge;
  };

  ## Merge function that insists all definitions agree. Used by ported
  ## nixpkgs code (`systemd-unit-options.nix`'s `unitOption` type) as the
  ## fallback merge when definitions are not lists.
  ## # Type
  ## `loc -> [def] -> a`
  mergeEqualOption = loc: defs:
    if defs == []
    then throw "mergeEqualOption: no definitions for option '${showLoc loc}'"
    else let
      first = (builtins.head defs).value;
      allEqual = builtins.all (d: d.value == first) defs;
    in
      if allEqual
      then first
      else throw "The option '${showLoc loc}' has conflicting definitions: ${showDefs defs}";

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

  ## Single-line string: any string that does not contain an embedded
  ## newline. Used for systemd unit Description= fields.
  singleLineStr = {
    name = "singleLineStr";
    description = "single-line string";
    check = v: builtins.isString v && builtins.match ".*\n.*" v == null;
    merge = loc: defs: let
      val = lastValue loc defs;
    in
      if builtins.match ".*\n.*" val != null
      then throw "The option '${showLoc loc}' must be a single-line string (no embedded newlines)."
      else val;
  };

  path = {
    name = "path";
    description = "path";
    check = v: builtins.isPath v || (builtins.isString v && builtins.substring 0 1 v == "/");
    merge = lastValue;
  };

  ## A path that is known to live inside the Nix store. Matches nixpkgs'
  ## `types.pathInStore` — used to harden options that should never
  ## reference /etc, /home, or other host paths (since AOS is a
  ## hermetic, image-based distribution those paths don't exist on the
  ## target anyway, and accidentally embedding them in the closure
  ## leaks non-store references).
  ##
  ## The check accepts both Nix path values and strings that begin
  ## with `/nix/store/`. It does NOT validate that the referenced
  ## store path exists (that's a build-time concern, not an
  ## eval-time one).
  pathInStore = {
    name = "pathInStore";
    description = "path inside the Nix store";
    check = v:
      (builtins.isPath v || builtins.isString v)
      && builtins.match "/nix/store/[^/]+(/.*)?" (builtins.toString v) != null;
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

  ## A value that is itself a type (an attrset carrying `check` and
  ## `merge` functions). Used as the declared type of
  ## `_module.freeformType` so the option system can hold a type value
  ## without treating its internal fields as generic config.
  ##
  ## Last-writer-wins merge matches how submodule options with
  ## identical option names resolve in the outer engine — if two base
  ## modules both set `freeformType`, the later definition wins.
  optionType = {
    name = "optionType";
    description = "module option type";
    check = v: builtins.isAttrs v && v ? check && v ? merge;
    merge = lastValue;
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

  ## Supports `mkBefore` / `mkAfter` ordering markers at two levels:
  ##   1. Wrapped around the whole definition value — `config.path =
  ##      mkAfter [a b c];` — the marker's priority is distributed to
  ##      every element in the inner list.
  ##   2. Wrapped around individual list elements — `config.path =
  ##      [ (mkBefore a) b (mkAfter c) ];` — each element carries its
  ##      own priority.
  ##
  ## Runs `elemType.merge` on each list element individually with a
  ## single-definition wrapper, so element types with non-trivial merges
  ## (notably `submodule`) get per-element evaluation. For simple element
  ## types whose merge is `lastValue`, behaviour is unchanged vs. the
  ## pre-upgrade version.
  ## # Type
  ## `type -> type`
  listOf = elemType: {
    name = "listOf(${elemType.name})";
    description = "list of ${elemType.description}";
    check = v: builtins.isList v;
    merge = loc: defs: let
      # Wrap a single list element into a priority-tagged record. Honours
      # per-element `mkBefore` / `mkAfter` markers; otherwise inherits the
      # def-level default priority (`defPriority`).
      processElem = def: defPriority: elem:
        if isOrder elem
        then def // {
          value = elem._value;
          priority = elem._priority;
        }
        else def // {
          value = elem;
          priority = defPriority;
        };
      # Expand a def into its tagged element records. If the def's value
      # is itself an order marker (`mkAfter [...]`), the inner list is
      # extracted and the marker's priority becomes the default for every
      # element inside it.
      processDef = d:
        if isOrder d.value
        then builtins.map (processElem d d.value._priority) d.value._value
        else builtins.map (processElem d 1000) d.value;
      allElems = builtins.concatLists (builtins.map processDef defs);
      # Stable sort by priority (lower = earlier in the list).
      sorted = builtins.sort (a: b: a.priority < b.priority) allElems;
      resolveOne = i: e:
        elemType.merge
        (loc ++ ["[${builtins.toString i}]"])
        [
          (builtins.removeAttrs e ["priority"])
        ];
    in
      builtins.genList
      (i: resolveOne i (builtins.elemAt sorted i))
      (builtins.length sorted);
  };

  ## A list of `elemType` that must contain at least one element after
  ## merging. Delegates checking and merging to `listOf` and rejects an
  ## empty result at evaluation time.
  ## # Type
  ## `type -> type`
  nonEmptyListOf = elemType: let
    base = listOf elemType;
  in
    base
    // {
      name = "nonEmptyListOf(${elemType.name})";
      description = "non-empty ${base.description}";
      check = v: base.check v && v != [];
      merge = loc: defs: let
        merged = base.merge loc defs;
      in
        if merged == []
        then throw "The option '${showLoc loc}' must be a non-empty list, but is empty."
        else merged;
    };

  ## # Type
  ## `type -> type`
  attrsOf = elemType: {
    name = "attrsOf(${elemType.name})";
    description = "attribute set of ${elemType.description}";
    # Resolver provenance priority is applied independently to each dynamic
    # attribute, matching the ordinary mkOverride discharge performed here.
    # Without this marker a tier-75 host definition of one `/etc` entry would
    # discard every unrelated package/base entry in the attrsOf option.
    mergeProvenanceByKey = true;
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
      # For each key, collect its raw defs, unwrap override / mkIf /
      # mkMerge markers via dischargeProperties, and — critically —
      # drop keys whose def list became empty after filtering. A key
      # might be present in the outer attrset only as a `mkIf false`
      # contribution; in that case the key should not appear in the
      # final merged value at all, rather than hitting elemType.merge
      # with `[]` (which crashes any merge using `lastValue`).
      perKeyEntries = builtins.concatLists (
        builtins.map (
          key: let
            keyDefs =
              builtins.filter (d: builtins.hasAttr key d.value)
              (
                builtins.map (d:
                  d
                  // {_priority = d._priority or 100;})
                defs
              );
            valueDefs =
              builtins.map (d:
                d
                // {
                value = d.value.${key};
                _priority = d._priority or 100;
              })
              keyDefs;
            # Unwrap override / mkIf / mkMerge markers at the sub-
            # attribute level and keep only defs at the winning
            # priority. This lets
            #   `some.nested.field = lib.mkDefault "…";`
            # and
            #   `some.nested.field = lib.mkIf cond "…";`
            # work exactly like top-level option definitions.
            # A container must see every active definition: resolver priority
            # belongs to the concrete nested leaf, not to the dynamic attr key
            # as a whole. Filtering here would let a host write to one field
            # and accidentally erase unrelated package fields, and would make
            # host priority 75 incorrectly beat a nested package mkForce 50.
            filteredDefs =
              if elemType.mergeProvenanceByKey or false || elemType ? _submodule
              then peelProperties valueDefs
              else dischargeProperties valueDefs;
          in
            if filteredDefs == []
            then []
            else [
              {
                name = key;
                value = elemType.merge (loc ++ [key]) filteredDefs;
              }
            ]
        )
        uniqueKeys
      );
    in
      builtins.listToAttrs perKeyEntries;
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
          ((builtins.elemAt defs (builtins.length defs - 1)) // {value = val;})
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

  ## A submodule type: a typed attrset of options declared in a nested
  ## module. When `evalSubmodule` is available (i.e. after bootstrap), the
  ## merge function delegates to it and the submodule is evaluated with
  ## full nixpkgs semantics — defaults from nested mkOption fire, `mkIf`
  ## / `mkMerge` / `mkDefault` / `mkForce` inside the submodule take
  ## effect, and per-option type checking runs. The submodule argument
  ## may be a single module (attrset or function) or a list of modules,
  ## matching nixpkgs' calling convention.
  ##
  ## When `evalSubmodule` is null (bootstrap phase, before the modules
  ## engine has been constructed), falls back to a permissive deep merge
  ## — enough to get lib/default.nix's fixpoint wire-up off the ground
  ## and nothing more.
  ## # Type
  ## `(module | [module]) -> type`
  submodule = moduleArgs: {
    name = "submodule";
    description = "submodule";
    # A submodule is a structural container. Keep all active outer
    # definitions so resolver priority is applied independently to its nested
    # leaves; filtering the container at priority 75 would erase unrelated
    # package fields whenever host.nix overrides one sibling.
    mergeProvenanceByKey = true;
    check = builtins.isAttrs;
    merge = loc: defs:
      if evalSubmodule != null
      then evalSubmodule moduleArgs loc defs
      else builtins.foldl' (acc: def: deepMergeSub acc def.value) {} defs;
    _submodule = moduleArgs;
  };

  ## Wrap a type with an additional check predicate. The inner type's
  ## check runs first, then the extra check. Ported nixpkgs code uses
  ## this to attach systemd-specific service validation (`checkService`)
  ## to an `attrsOf unitOption` type.
  ## # Type
  ## `type -> (a -> bool) -> type`
  addCheck = type: check:
    type
    // {
      check = v: type.check v && check v;
    };

  ## A string that matches a regular expression (POSIX ERE).
  ## # Type
  ## `string -> type`
  strMatching = regex: {
    name = "strMatching";
    description = "string matching ${regex}";
    check = v: builtins.isString v && builtins.match regex v != null;
    merge = loc: defs: let
      val = lastValue loc defs;
    in
      if builtins.match regex val == null
      then throw "The option '${showLoc loc}' must match the regex '${regex}' but is '${val}'."
      else val;
  };

  ## A string whose merge concatenates all definitions with a separator.
  ## # Type
  ## `string -> type`
  separatedString = sep: {
    name = "separatedString";
    description = "string merged with '${sep}'";
    check = builtins.isString;
    merge = _loc: defs: builtins.concatStringsSep sep (builtins.map (d: d.value) defs);
  };

  ## A comma-separated string. Multiple definitions concatenate with
  ## commas. Used for mount option lists.
  commas = {
    name = "commas";
    description = "comma-separated string";
    check = builtins.isString;
    merge = _loc: defs: builtins.concatStringsSep "," (builtins.map (d: d.value) defs);
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

  ## A conflict-rejecting enumerated scalar: `uniq (enum values)`.
  ##
  ## This is the canonical merge for an **owned shared scalar** on a
  ## shared root — e.g. `firewall.forwardPolicy = uniqEnum [ "accept" "drop" ]`.
  ## `enum` constrains the value set; `uniq` makes two *disagreeing* equal-
  ## priority definitions a loud eval error ("conflicting definitions … must
  ## have a unique value") rather than silent last-wins, so a genuine
  ## disagreement between packages is resolved only by an explicit priority
  ## bump — legitimately the operator at tier 75. Two *agreeing* definitions
  ## (same value) merge cleanly. Equivalent to `uniq (enum values)`; provided
  ## as a named helper so owners declare the pattern at a glance.
  ##
  ## # Type
  ## `[a] -> type`
  uniqEnum = values: uniq (enum values);

  ## # Type
  ## `type -> type`
  uniq = elemType: {
    name = "uniq(${elemType.name})";
    description = "unique ${elemType.description}";
    check = elemType.check;
    # The module engine uses this marker only when structured evaluator
    # diagnostics are requested. Keeping the marker on the type (rather than
    # parsing a human error string) lets the native evaluator receive the
    # complete conflicting definition set as typed data.
    conflictOnDisagreement = true;
    merge = loc: defs: let
      first = builtins.elemAt defs 0;
      allSame = builtins.all (d: d.value == first.value) defs;
    in
      # Delegate the agreed value through the inner type's own merge so its
      # validity check fires (e.g. `enum` rejects an out-of-set value). AOS has
      # no engine-level `type.check` enforcement — each type validates inside its
      # `merge` — so returning the bare `.value` here would silently discard the
      # element type's constraint. `uniq` only adds the conflict-on-disagreement
      # rule; it must not bypass the element type.
      if allSame
      then elemType.merge loc [first]
      else throw "The option '${showLoc loc}' has conflicting definitions. It must have a unique value.";
  };
}
