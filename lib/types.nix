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
{
  evalSubmodule ? null,
  projectOptionType ? type: type._aosDocType,
}: let
  # Helper: take the last definition's value (last-writer-wins semantics).
  lastValue = _loc: defs: let
    last = builtins.elemAt defs (builtins.length defs - 1);
  in
    last.value;

  # Helper: format an option location for error messages.
  showLoc = loc: builtins.concatStringsSep "." loc;

  # Helper: show the source file and value of a definition.
  showDef = def: "${builtins.toJSON def.value} (defined in ${def.file})";

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
      builtins.map (d: peelDef d (d.condition or true) (d._priority or 100) d.value) defs
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
    aosDocType ? {
      kind = "opaque";
      signature = description;
    },
    ...
  }: {
    inherit name description check merge;
    _aosDocType = aosDocType;
  };

  ## Adds portable value constraints without changing the underlying module merge.
  refined = {
    type,
    constraints,
  }: let
    predicates = import ./types/constraints.nix;
    checked = builtins.map predicates.validate constraints;
  in
    type
    // {
      _refinementConstraints = (type._refinementConstraints or []) ++ checked;
      merge = loc: defs: let
        value = type.merge loc defs;
      in
        if builtins.deepSeq checked (predicates.check checked value)
        then value
        else throw "Option '${showLoc loc}' violates its portable refinement constraints.";
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
    _aosDocType = {kind = "bool";};
  };

  int = {
    name = "int";
    description = "signed integer";
    check = builtins.isInt;
    merge = lastValue;
    _aosDocType = {
      kind = "integer";
      min = null;
      max = null;
    };
  };

  ## Signed integer refinements with bounds retained across the runtime boundary.
  ## Unlike arbitrary predicates, both Nix and the portable validator can check these.
  ints = rec {
    between = minimum: maximum:
      if !builtins.isInt minimum || !builtins.isInt maximum || minimum > maximum
      then throw "types.ints.between requires ordered integer bounds"
      else
        (addCheck int (value: value >= minimum && value <= maximum))
        // {
          name = "intBetween";
          description = "integer between ${toString minimum} and ${toString maximum}";
          _portable = true;
          _aosDocType = {
            kind = "integer";
            min = minimum;
            max = maximum;
          };
        };
    unsigned = between 0 9223372036854775807;
    positive = between 1 9223372036854775807;
  };

  float = {
    name = "float";
    description = "floating point number";
    check = builtins.isFloat;
    merge = lastValue;
    _aosDocType = {
      kind = "opaque";
      signature = "floating point number";
    };
  };

  str = {
    name = "str";
    description = "string";
    check = builtins.isString;
    merge = lastValue;
    _aosDocType = {
      kind = "string";
      pattern = null;
      max_length = null;
    };
  };

  # lines — concatenates multiple string definitions with newlines
  lines = {
    name = "lines";
    description = "strings concatenated with newlines";
    check = builtins.isString;
    merge = _loc: defs: builtins.concatStringsSep "\n" (builtins.map (d: d.value) defs);
    _aosDocType = str._aosDocType;
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
    _aosDocType = str._aosDocType;
    _refinementConstraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
    ];
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
    _aosDocType = str._aosDocType;
    _refinementConstraints = [
      {
        kind = "string-excludes";
        classes = ["line-feed"];
      }
    ];
  };

  path = {
    name = "path";
    description = "path";
    check = v: builtins.isPath v || (builtins.isString v && builtins.substring 0 1 v == "/");
    merge = lastValue;
    _aosDocType = {kind = "path";};
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
    _aosDocType = {kind = "path";};
  };

  package = {
    name = "package";
    description = "package (derivation)";
    check = v: builtins.isAttrs v && (v ? outPath || v ? drvPath || v ? type && v.type == "derivation");
    merge = lastValue;
    _aosDocType = {
      kind = "opaque";
      signature = "package (derivation)";
    };
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

  ## Recursively mergeable canonical JSON, including typed deferred leaves.
  ## Functions, derivations, paths, and floating-point values are not JSON inputs.
  json = {
    name = "json";
    description = "canonical JSON value";
    mergeProvenanceByKey = true;
    check = value:
      value
      == null
      || builtins.isBool value
      || builtins.isString value
      || (builtins.isInt value && value >= -9007199254740991 && value <= 9007199254740991)
      || (builtins.isList value && builtins.all json.check value)
      || (builtins.isAttrs value
        && !(value ? outPath || value ? drvPath)
        && (
          if (value._type or null) == "aos-effect-output"
          then effectOutput.check value
          else builtins.all json.check (builtins.attrValues value)
        ));
    merge = loc: definitions: let
      active = peelProperties definitions;
      ordinaryObject = value: builtins.isAttrs value && !(value ? _type);
      merged =
        if builtins.all (definition: ordinaryObject definition.value) active
        then (attrsOf json).merge loc active
        else if builtins.all (definition: builtins.isList definition.value) active
        then (listOf json).merge loc (dischargeProperties active)
        else mergeEqualOption loc (dischargeProperties active);
    in
      if json.check merged
      then merged
      else throw "The option '${showLoc loc}' is not canonical JSON.";
    _aosDocType = {kind = "json";};
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

  ## An opaque function with one authoritative definition whose result is
  ## checked through the supplied result type.
  ## # Type
  ## `type -> type`
  functionTo = resultType: {
    name = "functionTo(${resultType.name})";
    description = "function returning ${resultType.description}";
    check = builtins.isFunction;
    merge = loc: defs:
      if builtins.length defs != 1
      then throw "The option '${showLoc loc}' must have one authoritative function definition."
      else let
        definition = builtins.head defs;
      in
        argument: let
          result = definition.value argument;
        in
          if resultType.check result
          then result
          else throw "The function at option '${showLoc loc}' returned a value outside ${resultType.description}.";
    _aosDocType = {
      kind = "opaque";
      signature = "function returning ${resultType.description}";
    };
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
    _aosDocType = {kind = "port";};
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
    _aosDocType =
      if builtins.all builtins.isString allowedValues
      then {
        kind = "enum";
        values =
          builtins.map (value: {
            inherit value;
          })
          allowedValues;
      }
      else if builtins.all builtins.isBool allowedValues
      then
        if builtins.all (value: value == builtins.head allowedValues) allowedValues
        then {
          kind = "refined";
          value = {kind = "bool";};
          constraints = [
            {
              kind = "boolean-value";
              value = builtins.head allowedValues;
            }
          ];
        }
        else {kind = "bool";}
      else {
        kind = "opaque";
        signature = "one of ${builtins.toJSON allowedValues}";
      };
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
    _nestedType = elemType;
    name = "listOf(${elemType.name})";
    description = "list of ${elemType.description}";
    check = v: builtins.isList v;
    merge = loc: defs: let
      # Wrap a single list element into a priority-tagged record. Honours
      # per-element `mkBefore` / `mkAfter` markers; otherwise inherits the
      # def-level default priority (`defPriority`).
      processElem = def: defPriority: elem:
        if isOrder elem
        then
          def
          // {
            value = elem._value;
            priority = elem._priority;
          }
        else
          def
          // {
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
      resolveOne = i: e: let
        merged =
          elemType.merge
          (loc ++ ["[${builtins.toString i}]"])
          [
            (builtins.removeAttrs e ["priority"])
          ];
      in
        if elemType ? _elementType || elemType.check merged
        then merged
        else throw "The option '${showLoc loc}' has an element that does not satisfy type '${elemType.description}'.";
    in
      builtins.genList
      (i: resolveOne i (builtins.elemAt sorted i))
      (builtins.length sorted);
    _aosDocType = {
      kind = "list";
      element =
        elemType._aosDocType
        or {
          kind = "opaque";
          signature = elemType.description;
        };
      unique = false;
    };
  };

  ## Constrains a mergeable list while preserving its element module type.
  listWith = {
    elemType,
    maxItems,
    unique ? false,
    canonicalOrder ? false,
  }: let
    base = listOf elemType;
    valid = value: let
      # Equality and ordering compare JSON bytes. Contexts on the original
      # values still retain artifacts, but cannot be used as attribute names.
      encoded = builtins.map (item: builtins.unsafeDiscardStringContext (builtins.toJSON item)) value;
      names = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
          inherit name;
          value = true;
        })
        encoded));
    in
      builtins.length value
      <= maxItems
      && (!unique || builtins.length names == builtins.length encoded)
      && (!canonicalOrder || encoded == builtins.sort builtins.lessThan encoded);
  in
    assert builtins.isInt maxItems && maxItems >= 0;
    assert !canonicalOrder || unique;
      (addCheck base valid)
      // {
        _portable = true;
        _aosDocType =
          base._aosDocType
          // {
            max_items = maxItems;
            inherit unique;
            canonical_order = canonicalOrder;
          };
      };

  ## Constrains dynamic keys and cardinality without changing per-key merging.
  attrsWith = {
    elemType,
    maxEntries,
    keyMaxLength,
    keySyntax ? null,
  }: let
    base = attrsOf elemType;
    keyValid = key:
      builtins.stringLength key
      <= keyMaxLength
      && (
        if keySyntax == null
        then builtins.match ".*[[:cntrl:]].*" key == null
        else if keySyntax == "local-key-v1"
        then builtins.stringLength key <= 128 && builtins.match "[A-Za-z0-9._-]+" key != null
        else throw "Unsupported map key syntax '${keySyntax}'."
      );
    valid = value:
      builtins.length (builtins.attrNames value)
      <= maxEntries
      && builtins.all keyValid (builtins.attrNames value);
  in
    assert builtins.isInt maxEntries && maxEntries >= 0;
    assert builtins.isInt keyMaxLength && keyMaxLength > 0;
      (addCheck base valid)
      // {
        _portable = true;
        _aosDocType = {
          kind = "map";
          key = {
            max_length = keyMaxLength;
            syntax = keySyntax;
          };
          max_entries = maxEntries;
          value = elemType._aosDocType;
        };
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
  attrsOfWith = lazy: elemType: {
    name = "${
      if lazy
      then "lazyAttrsOf"
      else "attrsOf"
    }(${elemType.name})";
    description = "attribute set of ${elemType.description}";
    # Resolver provenance priority is applied independently to each dynamic
    # attribute, matching the ordinary mkOverride discharge performed here.
    # Without this marker a tier-75 host definition of one `/etc` entry would
    # discard every unrelated package/base entry in the attrsOf option.
    mergeProvenanceByKey = true;
    _elementType = elemType;
    _lazyAttrsOf = lazy;
    check = v: builtins.isAttrs v && builtins.all elemType.check (builtins.attrValues v);
    merge = loc: defs: let
      # Index each definition once. Scanning every definition for every key
      # makes large dynamic option sets quadratic during system evaluation.
      definitionsByKey = builtins.groupBy (entry: entry.name) (
        builtins.concatMap (def:
          map (name: {
            inherit name;
            value =
              def
              // {
                value = def.value.${name};
                _priority = def._priority or 100;
              };
          }) (builtins.attrNames def.value))
        defs
      );
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
            valueDefs = map (entry: entry.value) definitionsByKey.${key};
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
            if !lazy && filteredDefs == []
            then []
            else [
              {
                name = key;
                value = let
                  merged = elemType.merge (loc ++ [key]) filteredDefs;
                in
                  if elemType ? _elementType || elemType.check merged
                  then merged
                  else throw "The option '${showLoc (loc ++ [key])}' does not satisfy type '${elemType.description}'.";
              }
            ]
        )
        (builtins.attrNames definitionsByKey)
      );
    in
      builtins.listToAttrs perKeyEntries;
    _aosDocType = {
      kind = "attrs-of";
      value =
        elemType._aosDocType
        or {
          kind = "opaque";
          signature = elemType.description;
        };
      placeholder = "name";
    };
  };

  attrsOf = attrsOfWith false;

  ## Keeps syntactically declared keys while resolving their conditions only
  ## when an individual value is demanded. This supports sibling submodules
  ## whose conditional definitions refer to each other's evaluated values.
  lazyAttrsOf = elemType:
    if elemType ? _submodule
    then attrsOfWith true elemType
    else throw "lazyAttrsOf requires a submodule element type";

  ## # Type
  ## `type -> type`
  nullOr = elemType: {
    _nestedType = elemType;
    name = "nullOr(${elemType.name})";
    description = "${elemType.description} or null";
    check = v: v == null || elemType.check v;
    # A nullable structural value still merges its non-null definitions at
    # nested option boundaries. Preserve their priorities for the inner type.
    mergeProvenanceByKey = elemType.mergeProvenanceByKey or false;
    merge = loc: defs: let
      structural = elemType.mergeProvenanceByKey or false;
      minPriority =
        builtins.foldl' (
          priority: def:
            if (def._priority or 100) < priority
            then def._priority or 100
            else priority
        )
        9999
        defs;
      winningDefs = builtins.filter (def: (def._priority or 100) == minPriority) defs;
      winningNull = builtins.any (def: def.value == null) winningDefs;
      winningValue = builtins.any (def: def.value != null) winningDefs;
      nonNullDefs = builtins.filter (def: def.value != null) defs;
    in
      if winningNull && winningValue
      then throw "The option '${showLoc loc}' has conflicting null and non-null definitions: ${showDefs winningDefs}"
      else if winningNull
      then null
      else if structural
      then elemType.merge loc nonNullDefs
      else elemType.merge loc winningDefs;
    _aosDocType = {
      kind = "nullable";
      value =
        elemType._aosDocType
        or {
          kind = "opaque";
          signature = elemType.description;
        };
    };
  };

  ## # Type
  ## `type -> type -> type`
  either = type1: type2: {
    _alternativeTypes = [type1 type2];
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
    _aosDocType = {
      kind = "one-of";
      alternatives = builtins.map (
        type:
          type._aosDocType
          or {
            kind = "opaque";
            signature = type.description;
          }
      ) [type1 type2];
    };
  };

  ## # Type
  ## `[type] -> type`
  oneOf = types: {
    _alternativeTypes = types;
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
    _aosDocType = {
      kind = "one-of";
      alternatives =
        builtins.map (
          type:
            type._aosDocType
            or {
              kind = "opaque";
              signature = type.description;
            }
        )
        types;
    };
  };

  ## A record union whose discriminator is merged before its selected module.
  ## Each variant remains a normal mergeable option type. Definitions may
  ## supply different fields, but conflicting discriminator values are errors.
  taggedUnion = tag: variants: {
    name = "taggedUnion(${tag})";
    description = "record selected by '${tag}'";
    mergeProvenanceByKey = true;
    _variantTypes = variants;
    check = value:
      builtins.isAttrs value
      && builtins.hasAttr tag value
      && builtins.isString value.${tag}
      && builtins.hasAttr value.${tag} variants
      && variants.${value.${tag}}.check value;
    merge = loc: definitions: let
      active = peelProperties definitions;
      tagDefinitions = dischargeProperties (builtins.concatMap (definition:
        if builtins.isAttrs definition.value && builtins.hasAttr tag definition.value
        then [(definition // {value = definition.value.${tag};})]
        else [])
      active);
      selected = mergeEqualOption (loc ++ [tag]) tagDefinitions;
    in
      if !(builtins.isString selected && builtins.hasAttr selected variants)
      then throw "The option '${showLoc loc}' has an unknown '${tag}' variant."
      else variants.${selected}.merge loc active;
    _aosDocType = {
      kind = "tagged-union";
      inherit tag;
      variants = builtins.mapAttrs (_: type: type._aosDocType) variants;
    };
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
      builtins.removeAttrs (
        if evalSubmodule != null
        then evalSubmodule moduleArgs loc defs
        else builtins.foldl' (acc: def: deepMergeSub acc def.value) {} defs
      ) ["_module"];
    _submodule = moduleArgs;
    _aosDocType = {
      kind = "submodule";
      fields = {};
      open = true;
    };
  };

  ## A module held as an option value for a later nested evaluation. It does
  ## not evaluate the module here; the consumer supplies its fixed-point
  ## context when it constructs the submodule type.
  deferredModule = {
    name = "deferredModule";
    description = "module evaluated by a later module fixed point";
    check = value:
      builtins.isFunction value
      || builtins.isPath value
      || (builtins.isAttrs value && !(value ? _type));
    merge = loc: defs:
      if
        builtins.all (definition:
          builtins.isFunction definition.value
          || builtins.isPath definition.value
          || (builtins.isAttrs definition.value && !(definition.value ? _type)))
        defs
      then
        if builtins.length defs == 1
        then (builtins.head defs).value
        else {imports = builtins.map (definition: definition.value) defs;}
      else throw "The option '${showLoc loc}' must contain module values.";
    _aosDocType = {
      kind = "opaque";
      signature = "deferred module";
    };
  };

  ## An output reference denotes a value available only during activation.
  ## Its schema travels with it so inputs can reject incompatible references
  ## during module evaluation without demanding the producer's execution.
  effectOutput = {
    name = "effectOutput";
    description = "typed deferred effect output";
    check = value:
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "identity" "output" "schema"]
      && value._type == "aos-effect-output"
      && builtins.isList value.identity
      && builtins.length value.identity >= 3
      && builtins.all builtins.isString value.identity
      && builtins.isString value.output
      && builtins.isAttrs value.schema;
    merge = mergeEqualOption;
  };

  ## Accepts an ordinary value or a deferred output of the same declared type.
  ## This wraps an option type; it does not construct graph expressions.
  deferred = valueType: {
    _nestedType = valueType;
    _deferred = true;
    name = "deferred(${valueType.name})";
    description = "${valueType.description} or its deferred result";
    check = value:
      if builtins.isAttrs value && (value._type or null) == "aos-effect-output"
      then effectOutput.check value && value.schema == projectOptionType valueType
      else valueType.check value;
    merge = loc: definitions:
      if
        builtins.any (definition:
          builtins.isAttrs definition.value
          && (definition.value._type or null) == "aos-effect-output")
        definitions
      then mergeEqualOption loc definitions
      else valueType.merge loc definitions;
    _aosDocType = valueType._aosDocType;
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
      _portable = false;
      check = v: type.check v && check v;
      # The module engine delegates validation to merge. Retain the extra
      # predicate there as well, including when this type is nested in a list
      # or submodule or its value comes from an option default.
      merge = loc: defs: let
        value = type.merge loc defs;
      in
        if type.check value && check value
        then value
        else throw "The option '${showLoc loc}' does not satisfy its type's additional check.";
    };

  ## Bounds UTF-8 bytes and optionally checks a whole-string pattern.
  strWith = {
    maxLength,
    pattern ? null,
  }: let
    base =
      if pattern == null
      then str
      else strMatching pattern;
  in
    assert builtins.isInt maxLength && maxLength > 0;
      (addCheck base (value: builtins.stringLength value <= maxLength))
      // {
        _portable = true;
        _aosDocType = base._aosDocType // {max_length = maxLength;};
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
      if !builtins.isString val
      then throw "The option '${showLoc loc}' must be a string matching '${regex}'."
      else if builtins.match regex val == null
      then throw "The option '${showLoc loc}' must match the regex '${regex}' but is '${val}'."
      else val;
    _aosDocType = {
      kind = "string";
      pattern = regex;
      max_length = null;
    };
  };

  ## A string whose merge concatenates all definitions with a separator.
  ## # Type
  ## `string -> type`
  separatedString = sep: {
    name = "separatedString";
    description = "string merged with '${sep}'";
    check = builtins.isString;
    merge = _loc: defs: builtins.concatStringsSep sep (builtins.map (d: d.value) defs);
    _aosDocType = str._aosDocType;
  };

  ## A comma-separated string. Multiple definitions concatenate with
  ## commas. Used for mount option lists.
  commas = {
    name = "commas";
    description = "comma-separated string";
    check = builtins.isString;
    merge = _loc: defs: builtins.concatStringsSep "," (builtins.map (d: d.value) defs);
    _aosDocType = str._aosDocType;
  };

  ## # Type combinators

  ## # Type
  ## `type -> (a -> b) -> type -> type`
  coercedTo = fromType: coercion: toType: {
    _projectionType = toType;
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
    _aosDocType =
      toType._aosDocType
      or {
        kind = "opaque";
        signature = toType.description;
      };
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
    _projectionType = elemType;
    name = "uniq(${elemType.name})";
    description = "unique ${elemType.description}";
    check = elemType.check;
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
    _aosDocType =
      elemType._aosDocType
      or {
        kind = "opaque";
        signature = elemType.description;
      };
  };
}
