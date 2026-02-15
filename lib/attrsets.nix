##! lib/attrsets.nix — Attribute set utility functions
##!
##! Functions for manipulating Nix attribute sets (dictionaries).

rec {
  ## # Accessors

  ## # Type
  ## `attrset -> [string]`
  attrNames = builtins.attrNames;

  ## # Type
  ## `attrset -> [a]`
  attrValues = builtins.attrValues;

  ## # Type
  ## `string -> attrset -> bool`
  hasAttr = builtins.hasAttr;

  ## # Type
  ## `string -> attrset -> a`
  getAttr = builtins.getAttr;

  ## # Type
  ## `a -> bool`
  isAttrs = builtins.isAttrs;

  ## # Construction

  ## Create a name-value pair suitable for listToAttrs.
  ## # Type
  ## `string -> a -> { name :: string; value :: a; }`
  nameValuePair = name: value: { inherit name value; };

  ## # Type
  ## `[{ name :: string; value :: a; }] -> attrset`
  listToAttrs = builtins.listToAttrs;

  ## Generate an attrset from a list of names and a function.
  ##
  ## `genAttrs ["a" "b"] (n: n + "!") == { a = "a!"; b = "b!"; }`
  ## # Type
  ## `[string] -> (string -> a) -> attrset`
  genAttrs =
    names: f:
    builtins.listToAttrs (
      builtins.map (name: {
        inherit name;
        value = f name;
      }) names
    );

  ## Return the attrset if condition is true, otherwise empty.
  ## # Type
  ## `bool -> attrset -> attrset`
  optionalAttrs = cond: attrs: if cond then attrs else { };

  ## # Mapping

  ## # Type
  ## `(string -> a -> b) -> attrset -> attrset`
  mapAttrs = builtins.mapAttrs;

  ## Map over an attrset and collect results into a list.
  ## # Type
  ## `(string -> a -> b) -> attrset -> [b]`
  mapAttrsToList = f: attrs: builtins.map (name: f name attrs.${name}) (builtins.attrNames attrs);

  ## Map over attrs, allowing renaming of keys.
  ## # Type
  ## `(string -> a -> { name :: string; value :: b; }) -> attrset -> attrset`
  mapAttrs' = f: attrs: builtins.listToAttrs (mapAttrsToList f attrs);

  ## Recursively map over leaf values in a nested attrset.
  ## The function receives the path (list of attribute names) and the leaf value.
  ## # Type
  ## `([string] -> a -> b) -> attrset -> attrset`
  mapAttrsRecursive =
    f: attrs:
    let
      go =
        path: set:
        builtins.mapAttrs (
          name: value:
          let
            newPath = path ++ [ name ];
          in
          if builtins.isAttrs value && !(value ? _type) then go newPath value else f newPath value
        ) set;
    in
    go [ ] attrs;

  ## Like mapAttrsRecursive but only recurse into attrsets satisfying a predicate.
  ## # Type
  ## `(attrset -> bool) -> ([string] -> a -> b) -> attrset -> attrset`
  mapAttrsRecursiveCond =
    cond: f: attrs:
    let
      go =
        path: set:
        builtins.mapAttrs (
          name: value:
          let
            newPath = path ++ [ name ];
          in
          if builtins.isAttrs value && cond value then go newPath value else f newPath value
        ) set;
    in
    go [ ] attrs;

  ## # Filtering

  ## Keep only attributes satisfying the predicate.
  ## # Type
  ## `(string -> a -> bool) -> attrset -> attrset`
  filterAttrs =
    pred: attrs:
    builtins.listToAttrs (
      builtins.filter (pair: pred pair.name pair.value) (mapAttrsToList nameValuePair attrs)
    );

  ## Recursively filter attributes.
  ## # Type
  ## `(string -> a -> bool) -> attrset -> attrset`
  filterAttrsRecursive =
    pred: attrs:
    builtins.listToAttrs (
      builtins.concatLists (
        mapAttrsToList (
          name: value:
          if !pred name value then
            [ ]
          else
            [
              {
                inherit name;
                value = if builtins.isAttrs value then filterAttrsRecursive pred value else value;
              }
            ]
        ) attrs
      )
    );

  ## # Folding

  ## Fold a list of attrsets, combining values for the same key.
  ## # Type
  ## `(a -> b -> b) -> b -> [attrset] -> attrset`
  foldAttrs =
    f: init: listOfAttrs:
    let
      allNames = builtins.concatLists (builtins.map builtins.attrNames listOfAttrs);
      uniqueNames =
        let
          go =
            acc: remaining:
            if remaining == [ ] then
              acc
            else
              let
                h = builtins.elemAt remaining 0;
                t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
              in
              if builtins.any (x: x == h) acc then go acc t else go (acc ++ [ h ]) t;
        in
        go [ ] allNames;
    in
    builtins.listToAttrs (
      builtins.map (name: {
        inherit name;
        value = builtins.foldl' (
          acc: attrs: if builtins.hasAttr name attrs then f attrs.${name} acc else acc
        ) init listOfAttrs;
      }) uniqueNames
    );

  ## Left fold over an attrset's key-value pairs.
  ## # Type
  ## `(b -> string -> a -> b) -> b -> attrset -> b`
  foldlAttrs =
    f: init: attrs:
    builtins.foldl' (acc: name: f acc name attrs.${name}) init (builtins.attrNames attrs);

  ## # Merging

  ## Deep merge two attrsets. Values in the second override the first.
  ## Recursion occurs only when both sides are attrsets (and not derivations).
  ## # Type
  ## `attrset -> attrset -> attrset`
  recursiveUpdate =
    lhs: rhs:
    let
      lhsNames = builtins.attrNames lhs;
      rhsNames = builtins.attrNames rhs;
      allNames =
        let
          combined = lhsNames ++ rhsNames;
          go =
            acc: remaining:
            if remaining == [ ] then
              acc
            else
              let
                h = builtins.elemAt remaining 0;
                t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
              in
              if builtins.any (x: x == h) acc then go acc t else go (acc ++ [ h ]) t;
        in
        go [ ] combined;
    in
    builtins.listToAttrs (
      builtins.map (
        name:
        let
          lhsHas = builtins.hasAttr name lhs;
          rhsHas = builtins.hasAttr name rhs;
          lhsVal = lhs.${name} or null;
          rhsVal = rhs.${name} or null;
        in
        {
          inherit name;
          value =
            if lhsHas && rhsHas then
              if
                builtins.isAttrs lhsVal && builtins.isAttrs rhsVal && !(lhsVal ? outPath) && !(rhsVal ? outPath)
              then
                recursiveUpdate lhsVal rhsVal
              else
                rhsVal
            else if rhsHas then
              rhsVal
            else
              lhsVal;
        }
      ) allNames
    );

  ## Like recursiveUpdate but stop recursing when the predicate returns true.
  ## # Type
  ## `([string] -> attrset -> attrset -> bool) -> attrset -> attrset -> attrset`
  recursiveUpdateUntil =
    pred: lhs: rhs:
    let
      go =
        path: l: r:
        let
          lNames = builtins.attrNames l;
          rNames = builtins.attrNames r;
          allNames =
            let
              combined = lNames ++ rNames;
              dedup =
                acc: remaining:
                if remaining == [ ] then
                  acc
                else
                  let
                    h = builtins.elemAt remaining 0;
                    t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
                  in
                  if builtins.any (x: x == h) acc then dedup acc t else dedup (acc ++ [ h ]) t;
            in
            dedup [ ] combined;
        in
        builtins.listToAttrs (
          builtins.map (
            name:
            let
              lHas = builtins.hasAttr name l;
              rHas = builtins.hasAttr name r;
              lVal = l.${name} or null;
              rVal = r.${name} or null;
              newPath = path ++ [ name ];
            in
            {
              inherit name;
              value =
                if lHas && rHas then
                  if builtins.isAttrs lVal && builtins.isAttrs rVal && !pred newPath lVal rVal then
                    go newPath lVal rVal
                  else
                    rVal
                else if rHas then
                  rVal
                else
                  lVal;
            }
          ) allNames
        );
    in
    go [ ] lhs rhs;

  ## # Extraction

  ## Collect attribute values from a list of attrsets (skipping those without the key).
  ## # Type
  ## `string -> [attrset] -> [a]`
  catAttrs = builtins.catAttrs;

  ## Recursively collect leaf values satisfying a predicate from a nested attrset.
  ## # Type
  ## `(a -> bool) -> attrset -> [a]`
  collect =
    pred: attrs:
    if pred attrs then
      [ attrs ]
    else if builtins.isAttrs attrs then
      builtins.concatLists (builtins.map (name: collect pred attrs.${name}) (builtins.attrNames attrs))
    else
      [ ];

  ## Recursively collect all leaf (non-attrset) values from a nested attrset.
  ## # Type
  ## `attrset -> [a]`
  collectLeaves =
    attrs:
    if !builtins.isAttrs attrs then
      [ attrs ]
    else
      builtins.concatLists (builtins.map (name: collectLeaves attrs.${name}) (builtins.attrNames attrs));

  ## # Zipping

  ## Merge a list of attrsets, collecting values for duplicate keys into lists.
  ##
  ## `zipAttrs [{ a = 1; } { a = 2; b = 3; }] == { a = [1 2]; b = [3]; }`
  ## # Type
  ## `[attrset] -> attrset`
  zipAttrs =
    listOfAttrs:
    let
      allNames = builtins.concatLists (builtins.map builtins.attrNames listOfAttrs);
      uniqueNames =
        let
          go =
            acc: remaining:
            if remaining == [ ] then
              acc
            else
              let
                h = builtins.elemAt remaining 0;
                t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
              in
              if builtins.any (x: x == h) acc then go acc t else go (acc ++ [ h ]) t;
        in
        go [ ] allNames;
    in
    builtins.listToAttrs (
      builtins.map (name: {
        inherit name;
        value = builtins.concatLists (
          builtins.map (attrs: if builtins.hasAttr name attrs then [ attrs.${name} ] else [ ]) listOfAttrs
        );
      }) uniqueNames
    );

  ## Like zipAttrs but apply a combining function to the collected values.
  ## # Type
  ## `(string -> [a] -> b) -> [attrset] -> attrset`
  zipAttrsWith = f: listOfAttrs: builtins.mapAttrs f (zipAttrs listOfAttrs);

  ## # Lookup

  ## Look up a nested attribute by a path of key names, with a default.
  ## # Type
  ## `[string] -> a -> attrset -> a`
  attrByPath =
    path: default: attrs:
    let
      go =
        remaining: current:
        if remaining == [ ] then
          current
        else
          let
            h = builtins.elemAt remaining 0;
            t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
          in
          if builtins.isAttrs current && builtins.hasAttr h current then go t current.${h} else default;
    in
    go path attrs;

  ## Test whether a nested attribute path exists.
  ## # Type
  ## `[string] -> attrset -> bool`
  hasAttrByPath =
    path: attrs:
    let
      go =
        remaining: current:
        if remaining == [ ] then
          true
        else
          let
            h = builtins.elemAt remaining 0;
            t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
          in
          if builtins.isAttrs current && builtins.hasAttr h current then go t current.${h} else false;
    in
    go path attrs;

  ## Create a nested attrset with a single leaf value at the given path.
  ##
  ## `setAttrByPath ["a" "b" "c"] 42 == { a = { b = { c = 42; }; }; }`
  ## # Type
  ## `[string] -> a -> attrset`
  setAttrByPath =
    path: value:
    let
      len = builtins.length path;
      go = i: if i >= len then value else { ${builtins.elemAt path i} = go (i + 1); };
    in
    if len == 0 then value else go 0;

  ## Get a specific output of a multi-output derivation.
  ## # Type
  ## `string -> derivation -> derivation`
  getOutput = output: drv: if drv ? outputSpecified && drv ? ${output} then drv.${output} else drv;

  ## # Conversion

  ## # Type
  ## `attrset -> [{ name :: string; value :: a; }]`
  attrsToList =
    attrs:
    builtins.map (name: {
      inherit name;
      value = attrs.${name};
    }) (builtins.attrNames attrs);

  ## # Type
  ## `attrset -> [string] -> attrset`
  removeAttrs = builtins.removeAttrs;

  ## # Type
  ## `attrset -> attrset -> attrset`
  intersectAttrs = builtins.intersectAttrs;

  ## Update only attributes that already exist in the original.
  ## # Type
  ## `attrset -> attrset -> attrset`
  overrideExisting = old: new: builtins.mapAttrs (name: value: new.${name} or value) old;
}
