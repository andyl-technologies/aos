##! Package-output selector normalization at the package carrier boundary.
{
  diagnostics,
  limits ? {
    maxCollectionItems = 2000000;
    maxStringBytes = 1048576;
    maxStructuralDepth = 64;
  },
}: let
  marker = "aos-package-output-selector";
  inherit (limits) maxCollectionItems maxStringBytes maxStructuralDepth;
  fail = message:
    diagnostics.throw "value-type-mismatch" "abilities: ${message}";

  isLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;
  requireLocalKey = context: value:
    if isLocalKey value
    then value
    else fail "${context} must match [A-Za-z0-9._-]+ and contain at most 128 bytes";

  checkedCount = count:
    if count > maxCollectionItems
    then fail "package output selector value exceeds ${toString maxCollectionItems} aggregate collection items"
    else count;
  reverseList = builtins.foldl' (reversed: value: [value] ++ reversed) [];

  selectorLessThan = left: right:
    if left.package != right.package
    then left.package < right.package
    else left.output < right.output;
  sameSelector = left: right:
    left.package == right.package && left.output == right.output;

  canonicalizePackageOutputSelectors = selectors: let
    sorted = builtins.sort selectorLessThan selectors;
    deduplicated = builtins.foldl' (reversed: selector:
      if reversed != [] && sameSelector (builtins.head reversed) selector
      then reversed
      else [selector] ++ reversed) []
    sorted;
  in
    reverseList deduplicated;

  collect = depth: value:
    if depth > maxStructuralDepth
    then fail "package output selector collection exceeds ${toString maxStructuralDepth} structural levels"
    else if builtins.isList value
    then builtins.concatLists (builtins.map (collect (depth + 1)) value)
    else if builtins.isAttrs value && (value._type or null) == marker
    then
      if builtins.attrNames value != ["_type" "output" "package"]
      then fail "package output selector must contain only _type, package, and output"
      else if value.package == "self"
      then fail "source-stage package output selector still refers to self"
      else [
        {
          package = requireLocalKey "package output package" value.package;
          output = requireLocalKey "package output output" value.output;
        }
      ]
    else if builtins.isAttrs value
    then builtins.concatLists (builtins.map (name: collect (depth + 1) value.${name}) (builtins.attrNames value))
    else [];

  collectPackageOutputSelectors = value: let
    selectors = collect 1 value;
  in
    if builtins.length selectors > maxCollectionItems
    then fail "package output selector collection exceeds ${toString maxCollectionItems} selectors"
    else canonicalizePackageOutputSelectors selectors;

  normalize = owner: depth: count: value:
    if depth > maxStructuralDepth
    then fail "package output selector value exceeds ${toString maxStructuralDepth} structural levels"
    else if builtins.isList value
    then let
      initial = {
        count = checkedCount (count + builtins.length value);
        values = [];
      };
      normalized =
        builtins.foldl' (state: item: let
          result = normalize owner (depth + 1) state.count item;
        in {
          count = result.count;
          values = [result.value] ++ state.values;
        })
        initial
        value;
    in {
      inherit (normalized) count;
      value = reverseList normalized.values;
    }
    else if builtins.isAttrs value && (value._type or null) == marker
    then
      if builtins.attrNames value != ["_type" "output" "package"]
      then fail "package output selector must contain only _type, package, and output"
      else {
        count = checkedCount (count + 3);
        value = {
          _type = marker;
          package =
            if requireLocalKey "package output package" value.package == "self"
            then owner
            else value.package;
          output = requireLocalKey "package output output" value.output;
        };
      }
    else if builtins.isAttrs value
    then let
      names = builtins.attrNames value;
      initial = {
        count = checkedCount (count + builtins.length names);
        values = [];
      };
      normalized = builtins.foldl' (state: name:
        if builtins.stringLength name > maxStringBytes
        then fail "package output selector value contains an oversized member name"
        else let
          result = normalize owner (depth + 1) state.count value.${name};
        in {
          count = result.count;
          values =
            [
              {
                inherit name;
                value = result.value;
              }
            ]
            ++ state.values;
        })
      initial
      names;
    in {
      inherit (normalized) count;
      value = builtins.listToAttrs normalized.values;
    }
    else if builtins.isString value && builtins.stringLength value > maxStringBytes
    then fail "package output selector value contains an oversized string"
    else {inherit count value;};
in {
  inherit canonicalizePackageOutputSelectors collectPackageOutputSelectors;

  normalizePackageOutputSelectors = {
    owner,
    value,
  }: let
    result = normalize (requireLocalKey "ability package owner" owner) 1 0 value;
  in
    builtins.seq result.count result.value;
}
