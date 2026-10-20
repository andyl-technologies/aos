##! Data constraints checked after module merging and again after deferred resolution.
let
  at = path: value:
    builtins.foldl' (current: key:
      if builtins.isAttrs current && current ? ${key}
      then current.${key}
      else throw "Refinement path '${builtins.concatStringsSep "." path}' is unavailable.")
    value
    path;
  distinct = values: let
    keys = builtins.map builtins.toJSON values;
  in
    builtins.length keys
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = true;
      })
      keys)));
  deferred = value:
    if builtins.isAttrs value
    then (value._type or null) == "aos-effect-output" || builtins.any deferred (builtins.attrValues value)
    else builtins.isList value && builtins.any deferred value;
  supported = ["boolean-value" "string-pattern" "minimum-size" "integer-set" "map-keys-pattern" "string-excludes" "at-most-one-non-null" "unique-at" "disjoint-at" "subset-unless"];
  validate = constraint:
    if !(builtins.elem (constraint.kind or null) supported)
    then throw "Unsupported portable refinement '${constraint.kind or "<missing>"}'."
    else if builtins.elem constraint.kind ["string-pattern" "map-keys-pattern"]
    then constraint // {pattern = (import ./portable-pattern.nix) constraint.pattern;}
    else constraint;
  satisfies = constraint: value:
    if constraint.kind == "boolean-value"
    then builtins.isBool value && value == constraint.value
    else if constraint.kind == "string-pattern"
    then builtins.isString value && builtins.match constraint.pattern value != null
    else if constraint.kind == "minimum-size"
    then
      (
        if builtins.isString value
        then builtins.stringLength value
        else if builtins.isList value
        then builtins.length value
        else if builtins.isAttrs value
        then builtins.length (builtins.attrNames value)
        else -1
      )
      >= constraint.minimum
    else if constraint.kind == "integer-set"
    then builtins.isInt value && builtins.elem value constraint.values
    else if constraint.kind == "map-keys-pattern"
    then builtins.isAttrs value && builtins.all (key: builtins.match constraint.pattern key != null) (builtins.attrNames value)
    else if constraint.kind == "string-excludes"
    then
      builtins.isString value
      && builtins.all (class:
        if class == "ascii-control"
        then builtins.match "[^[:cntrl:]]*" value != null
        else if class == "ascii-space"
        then builtins.match "[^ ]*" value != null
        else if class == "ascii-whitespace"
        then builtins.match "[^[:space:]]*" value != null
        else if class == "line-break"
        then builtins.match "[^\n\r]*" value != null
        else if class == "line-feed"
        then builtins.match "[^\n]*" value != null
        else throw "Unknown excluded character class '${class}'.")
      constraint.classes
    else if constraint.kind == "at-most-one-non-null"
    then builtins.length (builtins.filter (field: (value.${field} or null) != null) constraint.fields) <= 1
    else if constraint.kind == "unique-at"
    then distinct (at constraint.path value)
    else if constraint.kind == "disjoint-at"
    then builtins.all (item: !(builtins.elem item (at constraint.right value))) (at constraint.left value)
    else if constraint.kind == "subset-unless"
    then at constraint.unless_path value == constraint.unless_equals || builtins.all (item: builtins.elem item (at constraint.superset value)) (at constraint.subset value)
    else throw "Unsupported portable refinement '${constraint.kind}'.";
in {
  inherit validate;
  # References are checked against their declared types here. Cross-field value
  # constraints become decidable once the runtime has substituted their results.
  check = constraints: value: deferred value || builtins.all (constraint: satisfies constraint value) constraints;
}
